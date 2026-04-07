import requests
import time
import json
import hmac
import hashlib
import base64
import os
import math
import threading
import uuid
import csv
import ssl
import certifi  # pip install certifi
import logging
from logging.handlers import RotatingFileHandler
import websocket  # pip install websocket-client
from datetime import datetime

# --- SSL / CA Bundle ---
# cacert.pem วางไว้ข้างๆ bot.py — ไม่ขึ้นกับ Windows system certificate store
_CA_BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cacert.pem")
_CA_BUNDLE_URL = "https://curl.se/ca/cacert.pem"  # แหล่งเดียวกับที่ certifi ใช้

def _refresh_ca_bundle() -> bool:
    """
    ดึง cacert.pem ใหม่จาก curl.se แล้ว save ทับไฟล์เดิม
    ใช้ verify=False เฉพาะ request นี้เท่านั้น เพราะยังไม่มี CA ที่ valid
    Return True ถ้า update สำเร็จ
    """
    try:
        resp = requests.get(_CA_BUNDLE_URL, verify=False, timeout=15)
        if resp.status_code == 200 and len(resp.content) > 1000:
            with open(_CA_BUNDLE, "wb") as f:
                f.write(resp.content)
            print(f"✅ [SSL] cacert.pem อัปเดตสำเร็จ ({len(resp.content):,} bytes)")
            return True
        else:
            print(f"⚠️ [SSL] cacert.pem response ผิดปกติ (status={resp.status_code})")
            return False
    except Exception as e:
        print(f"⚠️ [SSL] ดึง cacert.pem ไม่ได้: {e}")
        return False

def _build_ssl_context() -> ssl.SSLContext:
    """
    สร้าง SSL context จาก cacert.pem ที่มีอยู่
    ถ้าไม่มีไฟล์ → ดึงใหม่ก่อน
    """
    if not os.path.exists(_CA_BUNDLE):
        print("⚠️ [SSL] ไม่พบ cacert.pem — กำลังดึงใหม่...")
        _refresh_ca_bundle()

    if os.path.exists(_CA_BUNDLE):
        ctx = ssl.create_default_context(cafile=_CA_BUNDLE)
        print(f"🔒 [SSL] SSL context พร้อม (cacert.pem)")
        return ctx
    else:
        # Fallback: ใช้ default context ของ OS (อาจใช้ไม่ได้บน VPS)
        print("⚠️ [SSL] ใช้ default SSL context (cacert.pem ไม่มี)")
        return ssl.create_default_context()

# สร้าง SSL_CONTEXT ครั้งแรกตอน import
SSL_CONTEXT = _build_ssl_context()

# --- Bot States ---
STATE_INITIALIZED = "INITIALIZED"
STATE_ENTERED_LONG = "ENTERED_LONG"
STATE_ENTERED_SHORT = "ENTERED_SHORT"

class KcSigner:
    def __init__(self, api_key, api_secret, api_passphrase):
        self.api_key = api_key
        self.api_secret = api_secret
        self.api_secret_bytes = api_secret.encode('utf-8')
        self.api_passphrase = api_passphrase
        if api_passphrase and api_secret:
            self.api_passphrase = self._hmac_sign(api_passphrase)

    def _hmac_sign(self, message):
        signature = hmac.new(self.api_secret_bytes, message.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(signature.digest()).decode()

    def get_headers(self, method, endpoint, body=""):
        now = str(int(time.time() * 1000))
        str_to_sign = now + method + endpoint + body
        signature = self._hmac_sign(str_to_sign)
        return {
            "KC-API-KEY": self.api_key,
            "KC-API-SIGN": signature,
            "KC-API-PASSPHRASE": self.api_passphrase,
            "KC-API-TIMESTAMP": now,
            "KC-API-KEY-VERSION": "3",
            "Content-Type": "application/json"
        }

# =============================================================================
# BotLogger — จัดการ bot.log และ tradehistory.csv
# =============================================================================
class BotLogger:
    """
    ระบบ Logging สำหรับ KuCoin Hedge Bot
    
    bot.log:
        Level 1 → ERROR + WARNING เท่านั้น
        Level 2 → เพิ่ม INFO (state changes)
        RotatingFileHandler: max 10MB, เก็บ 5 ไฟล์
    
    tradehistory.csv:
        บันทึกเฉพาะเมื่อมีการยิง order
        RotatingFileHandler ขนาดกำหนดใน config (trade_history_max_mb)
    """

    CSV_HEADERS = [
        "timestamp", "state", "reason",
        "order_side", "order_size", "total_future_position", "order_price", "fill_status",
        "futures_account_usd", "total_port_usd", "order_id"
    ]

    def __init__(self, log_level: int = 2, trade_history_max_mb: float = 50.0):
        self.log_level = log_level  # 1=errors only, 2=errors+state changes

        # ------------------------------------------------------------------
        # bot.log — RotatingFileHandler 10MB × 5 files
        # ------------------------------------------------------------------
        self._logger = logging.getLogger("KuCoinBot")
        self._logger.setLevel(logging.DEBUG)
        self._logger.handlers.clear()  # ป้องกัน duplicate handlers

        bot_handler = RotatingFileHandler(
            "bot.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding="utf-8"
        )
        bot_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        self._logger.addHandler(bot_handler)

        # ------------------------------------------------------------------
        # tradehistory.csv — RotatingFileHandler ตาม config
        # ------------------------------------------------------------------
        self._csv_path = "tradehistory.csv"
        self._csv_max_bytes = int(trade_history_max_mb * 1024 * 1024)
        self._csv_lock = threading.Lock()  # thread-safe write
        self._ensure_csv_header()

        print(f"📋 [LOG] bot.log ready (level={log_level}) | "
              f"tradehistory.csv ready (max={trade_history_max_mb}MB)")

    # ------------------------------------------------------------------
    # bot.log helpers
    # ------------------------------------------------------------------
    def error(self, message: str):
        """Level 1+: API errors, order errors, WS errors"""
        self._logger.error(message)

    def warning(self, message: str):
        """Level 1+: spread too wide, WS reconnect, partial fill, timeout"""
        self._logger.warning(message)

    def state_change(self, from_state: str, to_state: str, reason: str):
        """Level 2 only: state transitions"""
        if self.log_level >= 2:
            self._logger.info(f"STATE {from_state} → {to_state} | reason={reason}")

    # ------------------------------------------------------------------
    # tradehistory.csv helpers
    # ------------------------------------------------------------------
    def _ensure_csv_header(self):
        """สร้างไฟล์ + header ถ้ายังไม่มี"""
        if not os.path.exists(self._csv_path) or os.path.getsize(self._csv_path) == 0:
            with open(self._csv_path, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(self.CSV_HEADERS)

    def _rotate_csv_if_needed(self):
        """Rotate CSV ถ้าขนาดเกิน limit — เปลี่ยนชื่อเป็น tradehistory.1.csv"""
        if os.path.exists(self._csv_path):
            if os.path.getsize(self._csv_path) >= self._csv_max_bytes:
                backup = self._csv_path.replace(".csv", ".1.csv")
                if os.path.exists(backup):
                    os.remove(backup)
                os.rename(self._csv_path, backup)
                self._ensure_csv_header()
                print(f"🔄 [LOG] tradehistory.csv rotated → tradehistory.1.csv")

    def log_trade(
        self,
        state: str,
        reason: str,
        order_side: str,
        order_size: int,
        total_future_position: int,    # net contracts: Σlong - Σshort (มักติดลบเพราะ bot เน้น short)
        order_price,                   # float | "N/A (estimated: XXXXX)"
        fill_status: str,              # "full" | "partial" | "timeout" | "test"
        futures_account_usd: float,
        total_port_usd: float,
        order_id: str
    ):
        """
        บันทึก 1 แถวลง tradehistory.csv
        เรียกหลังจาก poll_order_fill() เสร็จเท่านั้น
        """
        row = [
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            state,
            reason,
            order_side,
            order_size,
            total_future_position,     # net contracts ณ ขณะยิง order
            f"{order_price:.2f}" if isinstance(order_price, float) else str(order_price),
            fill_status,
            f"{futures_account_usd:.2f}",
            f"{total_port_usd:.2f}",
            order_id
        ]
        with self._csv_lock:
            self._rotate_csv_if_needed()
            with open(self._csv_path, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(row)


class KuCoinPublicWS:
    """
    Public Websocket สำหรับ KuCoin Futures
    Subscribe: /contractMarket/tickerV2:{symbol}
    Token: POST /api/v1/bullet-public (ไม่ต้อง API Key)

    shared_data fields:
        ws_connected (bool)  : True เมื่อ connected + ack แล้ว
        best_bid     (float) : Best Bid Price
        best_ask     (float) : Best Ask Price
        mid_price    (float) : (bid + ask) / 2  ← ใช้แทน last price
    """

    BASE_REST = "https://api-futures.kucoin.com"

    def __init__(self, symbol: str, shared_data: dict):
        self.symbol = symbol
        self.shared_data = shared_data          # reference เดียวกับที่ bot ใช้
        self._ws = None                         # websocket.WebSocketApp
        self._ping_thread = None                # threading.Thread
        self._ping_interval_ms = 18000          # default จาก docs, override ด้วย server value
        self._stop_event = threading.Event()    # สัญญาณหยุด ping loop

    # ------------------------------------------------------------------
    # 1. ขอ Public Token (REST)
    # POST /api/v1/bullet-public — ไม่ต้อง auth
    # ------------------------------------------------------------------
    def _get_public_token(self):
        """
        REST: POST https://api-futures.kucoin.com/api/v1/bullet-public
        Returns: (token, endpoint_url, ping_interval_ms) หรือ (None, None, None)
        """
        try:
            resp = requests.post(
                f"{self.BASE_REST}/api/v1/bullet-public",
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            data = resp.json()
            if data.get("code") != "200000":
                print(f"❌ [WS] bullet-public failed: {data}")
                return None, None, None

            token = data["data"]["token"]
            server = data["data"]["instanceServers"][0]
            endpoint = server["endpoint"]                   # dynamic URL จาก server
            ping_ms = int(server.get("pingInterval", 18000))
            return token, endpoint, ping_ms

        except Exception as e:
            print(f"❌ [WS] _get_public_token error: {e}")
            return None, None, None

    # ------------------------------------------------------------------
    # 2. Heartbeat loop (ส่ง ping ทุก pingInterval วินาที)
    # ------------------------------------------------------------------
    def _heartbeat_loop(self):
        """ส่ง ping ทุก pingInterval ms ตาม spec ของ KuCoin"""
        interval_sec = self._ping_interval_ms / 1000
        while not self._stop_event.is_set():
            time.sleep(interval_sec)
            if self._ws and not self._stop_event.is_set():
                try:
                    ping_msg = json.dumps({
                        "id": str(int(time.time() * 1000)),
                        "type": "ping"
                    })
                    self._ws.send(ping_msg)
                except Exception as e:
                    print(f"⚠️ [WS] Heartbeat error: {e}")
                    break

    # ------------------------------------------------------------------
    # 3. WebSocketApp callbacks
    # ------------------------------------------------------------------
    def _on_open(self, ws):
        """รอ welcome message ก่อน subscribe (ตาม docs)"""
        print(f"🔌 [WS] Connection opened — รอ welcome message...")

    def _on_message(self, ws, raw):
        try:
            msg = json.loads(raw)
            msg_type = msg.get("type")

            # 3a. Welcome → subscribe
            if msg_type == "welcome":
                print(f"✅ [WS] Welcome received — subscribing tickerV2:{self.symbol}")
                sub_msg = json.dumps({
                    "id": str(int(time.time() * 1000)),
                    "type": "subscribe",
                    "topic": f"/contractMarket/tickerV2:{self.symbol}",
                    "privateChannel": False,
                    "response": True
                })
                ws.send(sub_msg)

            # 3b. Ack → subscription สำเร็จ
            elif msg_type == "ack":
                print(f"✅ [WS] Subscribed to tickerV2:{self.symbol} — Websocket ready")
                self.shared_data["ws_connected"] = True

            # 3c. Pong → heartbeat ตอบกลับ (ไม่ต้องทำอะไร)
            elif msg_type == "pong":
                pass

            # 3d. Message → ข้อมูล ticker จริง
            elif msg_type == "message":
                subject = msg.get("subject", "")
                if subject == "tickerV2":
                    d = msg.get("data", {})
                    bid = float(d.get("bestBidPrice", 0) or 0)
                    ask = float(d.get("bestAskPrice", 0) or 0)
                    if bid > 0 and ask > 0:
                        self.shared_data["best_bid"] = bid
                        self.shared_data["best_ask"] = ask
                        self.shared_data["mid_price"] = (bid + ask) / 2

            # 3e. Error จาก server
            elif msg_type == "error":
                print(f"❌ [WS] Server error: {msg}")

        except Exception as e:
            print(f"⚠️ [WS] _on_message error: {e}")

    def _on_error(self, ws, error):
        print(f"❌ [WS] Error: {error}")

    def _on_close(self, ws, close_status_code, close_msg):
        self.shared_data["ws_connected"] = False
        self._stop_event.set()
        print(f"🔴 [WS] Connection closed (code={close_status_code}) — bot จะหยุดรอ reconnect")

    # ------------------------------------------------------------------
    # 4. Start (เรียกใน Thread แยก)
    # ------------------------------------------------------------------
    def start(self):
        """
        ขอ token → connect → เริ่ม heartbeat thread
        เรียกใช้จาก threading.Thread(target=ws.start)
        มี reconnect loop: ถ้า disconnect จะขอ token ใหม่แล้วเชื่อมต่อใหม่อัตโนมัติ
        """
        while True:
            # ดึง cacert.pem ใหม่ + rebuild SSL_CONTEXT ทุกครั้งที่ (re)connect
            # ทำให้ CA cert อัปเดตอัตโนมัติโดยไม่ต้อง restart bot
            _refresh_ca_bundle()
            global SSL_CONTEXT
            SSL_CONTEXT = _build_ssl_context()

            print(f"🌐 [WS] กำลังขอ Public Token...")
            token, endpoint, ping_ms = self._get_public_token()

            if not token:
                print("❌ [WS] ขอ Token ไม่สำเร็จ — retry ใน 10 วินาที")
                time.sleep(10)
                continue  # ← วนขอ token ใหม่

            self._ping_interval_ms = ping_ms
            connect_id = uuid.uuid4().hex
            ws_url = f"{endpoint}?token={token}&connectId={connect_id}"

            print(f"🌐 [WS] Connecting → {endpoint} (pingInterval={ping_ms}ms)")

            # reset stop_event และเริ่ม heartbeat thread ใหม่ทุกครั้งที่ reconnect
            self._stop_event.clear()
            self._ping_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True,
                name="ws-heartbeat"
            )
            self._ping_thread.start()

            # เชื่อมต่อ WebSocket (blocking จนกว่าจะ close)
            self._ws = websocket.WebSocketApp(
                ws_url,
                on_open=self._on_open,
                on_message=self._on_message,
                on_error=self._on_error,
                on_close=self._on_close,
            )
            # sslopt={"context": SSL_CONTEXT} → ใช้ certifi CA bundle
            # ไม่ขึ้นกับ Windows system certificate store
            self._ws.run_forever(sslopt={"context": SSL_CONTEXT})

            # ออกจาก run_forever = disconnect แล้ว → reconnect
            print("🔄 [WS] Reconnecting in 5 วินาที...")
            time.sleep(5)
            # วน while True → ขอ token ใหม่ → connect ใหม่


class KuCoinBot:
    def __init__(self, config):
        self.base_url = "https://api-futures.kucoin.com"
        self.symbol = config.get("symbol", "XBTUSDM")
        self.interval = config.get("check_interval_seconds", 10)
        self.cold_storage_amount = float(config.get("cold_storage_amount", 0))
        self.timeframe = int(config.get("timeframe", 1440))
        
        # Indicator Config
        self.ma_type = config.get("ma_type", "EMA").upper()
        self.ma_length = min(max(int(config.get("ma_length", 30)), 1), 990)
        self.band_calc = config.get("band_calculation", "SD").upper()
        self.band_length = min(max(int(config.get("band_length", 30)), 1), 990)
        self.band_mult = float(config.get("band_multiplier", 1.0))
        
        # Strategy Config
        self.max_spread_pct = float(config.get("max_spread_pct", 0.1))
        
        self.neutral_hedge_pct = float(config.get("neutral_hedge_pct", 100.0))
        self.neutral_dev_limit = float(config.get("neutral_deviation_limit_pct", 0.5))
        
        self.long_mode = str(config.get("long_mode", "rebalance")).lower()
        self.long_hedge_target = float(config.get("long_hedge_target_pct", 10.0))
        self.long_dev_limit = float(config.get("long_deviation_limit_pct", 1.0))
        self.long_rpt_pct = float(config.get("long_risk_per_trade_pct", 3.0))
        
        self.short_hedge_target = float(config.get("short_hedge_target_pct", 100.0))
        self.short_dev_limit = float(config.get("short_deviation_limit_pct", 0.5))
        
        # Order Execution Config
        # True  → POST /api/v1/orders/test  (ไม่เข้า matching system, ใช้ทดสอบ)
        # False → POST /api/v1/orders        (production จริง)
        self.use_test_endpoint = bool(config.get("use_test_endpoint", True))

        # Logging Config
        log_level            = int(config.get("log_level", 2))
        trade_history_max_mb = float(config.get("trade_history_max_mb", 50.0))
        self.logger = BotLogger(log_level, trade_history_max_mb)

        # Bot State Variables
        self.bot_state = STATE_INITIALIZED
        self.support_level = None
        self.resistance_level = None
        self.contract_multiplier = 1.0  # Default fallback

        # Cross Candle Tracking (Option A: ป้องกัน re-trigger cross เดิมหลัง SL)
        # เก็บ timestamp (ms) ของแท่ง T-1 ที่ trigger cross ล่าสุด
        # ถ้า T-1 ปัจจุบันมี timestamp เดิม → เป็น cross เดิม → ข้าม
        self.last_golden_cross_time = None  # int | None
        self.last_death_cross_time  = None  # int | None

        # Account Config (ดึงจาก API ตอน startup ใน _fetch_account_config)
        self.margin_mode   = "ISOLATED"  # "ISOLATED" | "CROSS"
        self.position_side = "BOTH"      # "BOTH" (one-way) | "SHORT" (hedge)
        self.leverage      = int(config.get("leverage", 1))  # fallback ถ้าไม่มี position
        
        self.signer = KcSigner(
            config.get("api_key"), 
            config.get("api_secret"), 
            config.get("api_passphrase")
        )

        # --- Websocket Shared Data ---
        # Bot loop อ่านค่าจาก dict นี้ (thread-safe สำหรับ read float/bool)
        self.ws_data = {
            "ws_connected": False,
            "best_bid":     0.0,
            "best_ask":     0.0,
            "mid_price":    0.0,
        }

        # เริ่ม Public Websocket Thread
        self._ws_client = KuCoinPublicWS(self.symbol, self.ws_data)
        ws_thread = threading.Thread(
            target=self._ws_client.start,
            daemon=True,
            name="ws-public"
        )
        ws_thread.start()
        print(f"🚀 [WS] Public Websocket thread started")

    def _request(self, method, path, params=None, body=None):
        url = self.base_url + path
        endpoint = path
        if params:
            query_string = "&".join([f"{k}={v}" for k, v in params.items()])
            url += "?" + query_string
            endpoint += "?" + query_string
        
        json_body = json.dumps(body) if body else ""
        headers = self.signer.get_headers(method, endpoint, json_body)
        
        try:
            resp = requests.request(
                method, url, headers=headers, data=json_body,
                verify=_CA_BUNDLE if os.path.exists(_CA_BUNDLE) else True
            )
            data = resp.json()
            if data.get('code') == '200000':
                return data.get('data')
            return None
        except:
            return None

    def _request_with_code(self, method, path, params=None, body=None):
        """
        เหมือน _request แต่ return (data, code) เพื่อให้ caller ตรวจ error code ได้
        ใช้สำหรับ place_market_order ที่ต้อง handle specific error codes
        """
        url = self.base_url + path
        endpoint = path
        if params:
            query_string = "&".join([f"{k}={v}" for k, v in params.items()])
            url += "?" + query_string
            endpoint += "?" + query_string

        json_body = json.dumps(body) if body else ""
        headers = self.signer.get_headers(method, endpoint, json_body)

        try:
            resp = requests.request(
                method, url, headers=headers, data=json_body,
                verify=_CA_BUNDLE if os.path.exists(_CA_BUNDLE) else True
            )
            data = resp.json()
            code = data.get('code', 'unknown')
            if code == '200000':
                return data.get('data'), code
            return None, code
        except Exception as e:
            print(f"❌ [ORDER] Request exception: {e}")
            return None, 'exception'

    # ------------------------------------------------------------------
    # REST: Account Config (ดึงตอน startup)
    # ------------------------------------------------------------------
    def get_position_mode(self):
        """
        GET /api/v2/position/getPositionMode
        Returns: positionMode int (0=one-way, 1=hedge) หรือ None
        """
        return self._request("GET", "/api/v2/position/getPositionMode")

    def get_margin_mode(self):
        """
        GET /api/v2/position/getMarginMode?symbol={symbol}
        Returns: {"symbol":..., "marginMode":"ISOLATED"|"CROSS"} หรือ None
        """
        return self._request("GET", "/api/v2/position/getMarginMode",
                             params={"symbol": self.symbol})

    def get_contract_info(self):
        return self._request("GET", f"/api/v1/contracts/{self.symbol}")

    def get_futures_balance(self, currency):
        return self._request("GET", "/api/v1/account-overview", params={"currency": currency})

    def get_active_position(self):
        return self._request("GET", "/api/v2/position", params={"symbol": self.symbol})

    def get_ticker_price(self):
        return self._request("GET", "/api/v1/ticker", params={"symbol": self.symbol})

    def get_kline_data(self):
        return self._request("GET", "/api/v1/kline/query", params={
            "symbol": self.symbol,
            "granularity": self.timeframe
        })

    # ------------------------------------------------------------------
    # _fetch_account_config: ดึง MarginMode + PositionMode + Leverage
    # เรียกตอน startup และเมื่อ order ถูก reject ด้วย mode error
    # ------------------------------------------------------------------
    def _fetch_account_config(self):
        """
        ดึง margin mode, position mode, leverage จาก API
        เก็บใน self.margin_mode, self.position_side, self.leverage
        """
        print("🔧 [CONFIG] กำลังดึง Account Config จาก API...")

        # 1. Position Mode: GET /api/v2/position/getPositionMode
        pos_mode_data = self.get_position_mode()
        if pos_mode_data is not None:
            pos_mode = int(pos_mode_data.get("positionMode", 0))
            # one-way (0) → BOTH, hedge (1) → SHORT (เพราะ bot เทรดฝั่ง Short เท่านั้น)
            self.position_side = "BOTH" if pos_mode == 0 else "SHORT"
            mode_label = "One-Way" if pos_mode == 0 else "Hedge"
            print(f"   Position Mode : {mode_label} → positionSide = '{self.position_side}'")
        else:
            print("   ⚠️ ดึง Position Mode ไม่ได้ ใช้ค่า default: positionSide = 'BOTH'")

        # 2. Margin Mode: GET /api/v2/position/getMarginMode?symbol=...
        margin_data = self.get_margin_mode()
        if margin_data:
            self.margin_mode = margin_data.get("marginMode", "ISOLATED")
            print(f"   Margin Mode   : {self.margin_mode}")
        else:
            print("   ⚠️ ดึง Margin Mode ไม่ได้ ใช้ค่า default: ISOLATED")

        # 3. Leverage: ดึงจาก position ปัจจุบัน (เฉพาะ ISOLATED)
        #    GET /api/v2/position?symbol=... (endpoint เดิมที่มีอยู่แล้ว)
        if self.margin_mode == "ISOLATED":
            pos_data = self.get_active_position()
            pos_list = pos_data if isinstance(pos_data, list) else ([pos_data] if pos_data else [])
            if pos_list and len(pos_list) > 0:
                pos = pos_list[0]
                lev = pos.get("leverage")
                if lev is not None:
                    self.leverage = int(float(lev))
                    print(f"   Leverage      : {self.leverage}x (จาก position จริง)")
                else:
                    print(f"   Leverage      : {self.leverage}x (fallback จาก config)")
            else:
                print(f"   Leverage      : {self.leverage}x (fallback จาก config — ยังไม่มี position)")
        else:
            # CROSS margin ไม่ต้องส่ง leverage ใน order
            print(f"   Leverage      : N/A (CROSS margin)")

        mode_str = "🧪 TEST" if self.use_test_endpoint else "🔴 PRODUCTION"
        print(f"   Order Mode    : {mode_str} endpoint")
        print("✅ [CONFIG] Account Config โหลดเสร็จแล้ว")

    # ------------------------------------------------------------------
    # get_order_by_id: GET /api/v1/orders/{order-id}
    # ------------------------------------------------------------------
    def get_order_by_id(self, order_id: str):
        """
        GET /api/v1/orders/{order-id}
        Returns: dict with keys: status, filledSize, avgDealPrice, size
        """
        return self._request("GET", f"/api/v1/orders/{order_id}")

    # ------------------------------------------------------------------
    # poll_order_fill: poll จนกว่า fill หรือ timeout
    # ------------------------------------------------------------------
    def poll_order_fill(self, order_id: str, requested_size: int, mid_price: float):
        """
        Poll GET /api/v1/orders/{order-id} จนกว่า status="done" หรือ timeout 10 วินาที

        Returns dict:
            fill_price  : float (avgDealPrice) หรือ float (mid_price ถ้า timeout)
            fill_status : "full" | "partial" | "timeout"
            filled_size : int
        """
        print(f"⏳ [ORDER] กำลัง poll fill status ของ order {order_id}...")

        deadline = time.time() + 10  # timeout 10 วินาที
        while time.time() < deadline:
            time.sleep(1)
            data = self.get_order_by_id(order_id)
            if not data:
                continue

            status      = data.get("status", "")
            filled_size = int(data.get("filledSize", 0))
            avg_price_s = data.get("avgDealPrice", "0")

            if status == "done":
                avg_price = float(avg_price_s) if avg_price_s and float(avg_price_s) > 0 else mid_price

                if filled_size >= requested_size:
                    # Full fill
                    print(f"✅ [ORDER] Full fill | size={filled_size} | avgPrice=${avg_price:,.2f}")
                    return {"fill_price": avg_price, "fill_status": "full", "filled_size": filled_size}
                else:
                    # Partial fill
                    msg = (f"Partial fill | filled={filled_size}/{requested_size} | "
                           f"avgPrice=${avg_price:,.2f} | orderId={order_id}")
                    print(f"⚠️ [ORDER] {msg}")
                    self.logger.warning(f"[ORDER] {msg}")
                    return {"fill_price": avg_price, "fill_status": "partial", "filled_size": filled_size}

        # Timeout
        msg = f"Poll timeout (10s) — order {order_id} ยังไม่ fill | ใช้ mid_price=${mid_price:,.2f} แทน"
        print(f"⚠️ [ORDER] {msg}")
        self.logger.warning(f"[ORDER] {msg}")
        return {"fill_price": mid_price, "fill_status": "timeout", "filled_size": 0}

    # ------------------------------------------------------------------
    # place_market_order: ส่ง Market Order จริง (หรือ test)
    # Endpoint: POST /api/v1/orders/test  หรือ  POST /api/v1/orders
    # ------------------------------------------------------------------
    def place_market_order(
        self,
        side: str,
        size: int,
        reason: str,
        total_usd: float,
        futures_usd: float,
        mid_price: float,
        current_position_qty: int = 0
    ):
        """
        ส่ง Market Order ไปยัง KuCoin Futures พร้อม fill tracking + logging

        Parameters:
            side                 : "buy" | "sell"
            size                 : จำนวน contracts (int, > 0)
            reason               : สาเหตุ เช่น "rebalance_neutral", "enter_long_rpt"
            total_usd            : มูลค่าพอร์ตรวม ณ ขณะยิง order (สำหรับ CSV)
            futures_usd          : มูลค่า futures account ณ ขณะยิง order (สำหรับ CSV)
            mid_price            : ราคากลาง ณ ขณะยิง order (fallback ถ้า poll timeout)
            current_position_qty : net contracts ก่อนยิง order (currentQty จาก position)
        """
        if size <= 0:
            print(f"⚠️ [ORDER] size={size} ไม่ถูกต้อง ข้ามการส่ง order")
            return

        # เลือก endpoint ตาม config
        endpoint = "/api/v1/orders/test" if self.use_test_endpoint else "/api/v1/orders"
        tag = "🧪 TEST" if self.use_test_endpoint else "🔴 LIVE"

        # สร้าง order body ตาม docs
        body = {
            "clientOid":    uuid.uuid4().hex,
            "symbol":       self.symbol,
            "side":         side,
            "type":         "market",
            "size":         size,
            "marginMode":   self.margin_mode,
            "positionSide": self.position_side,
        }
        if self.margin_mode == "ISOLATED":
            body["leverage"] = self.leverage

        print(f"{tag} [ORDER] Placing Market {side.upper()} {size} contracts | "
              f"marginMode={self.margin_mode} positionSide={self.position_side}"
              + (f" leverage={self.leverage}x" if self.margin_mode == "ISOLATED" else ""))

        # --- ส่ง order ครั้งแรก ---
        data, code = self._request_with_code("POST", endpoint, body=body)

        if code != '200000':
            # mode ไม่ตรง → re-fetch แล้ว retry 1 ครั้ง
            if code in ('330005', '330011'):
                msg = f"Order reject code={code} (mode mismatch) → re-fetch config แล้ว retry"
                print(f"⚠️ [ORDER] {msg}")
                self.logger.warning(f"[ORDER] {msg}")
                self._fetch_account_config()

                body["marginMode"]   = self.margin_mode
                body["positionSide"] = self.position_side
                body["clientOid"]    = uuid.uuid4().hex
                if self.margin_mode == "ISOLATED":
                    body["leverage"] = self.leverage
                else:
                    body.pop("leverage", None)

                data, code = self._request_with_code("POST", endpoint, body=body)

            if code != '200000':
                msg = (f"Order failed | endpoint={endpoint} | "
                       f"side={side} size={size} | code={code}")
                print(f"❌ [ORDER] {msg}")
                self.logger.error(f"[ORDER] {msg}")
                return

        order_id = data.get("orderId", "N/A") if data else "N/A"
        print(f"✅ [ORDER] Accepted | orderId: {order_id}")

        # --- Fill Tracking ---
        if self.use_test_endpoint:
            # Test endpoint ไม่เข้า matching system → ดึง fill price ไม่ได้
            fill_price  = mid_price
            fill_status = "test"
            filled_size = size
            print(f"🧪 [ORDER] Test mode — ใช้ mid_price=${mid_price:,.2f} แทน fill price")
        else:
            result      = self.poll_order_fill(order_id, size, mid_price)
            fill_price  = result["fill_price"]
            fill_status = result["fill_status"]
            filled_size = result["filled_size"]

        # --- บันทึก tradehistory.csv ---
        self.logger.log_trade(
            state                = self.bot_state,
            reason               = reason,
            order_side           = side,
            order_size           = filled_size,
            total_future_position = current_position_qty,  # net contracts ก่อนยิง order
            order_price          = fill_price,
            fill_status          = fill_status,
            futures_account_usd  = futures_usd,
            total_port_usd       = total_usd,
            order_id             = order_id
        )

    # ------------------------------------------------------------------
    # State Snapshot: save / restore  (state.json)
    # ------------------------------------------------------------------
    _STATE_FILE = "state.json"

    def save_state(self, current_hedge_ratio: float = 0.0, current_position_qty: int = 0):
        """
        บันทึก bot state ลง state.json (overwrite ทุกครั้ง — เก็บแค่ snapshot ล่าสุด)
        เรียกทุก loop หลัง display section
        """
        snapshot = {
            "timestamp":             datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "bot_state":             self.bot_state,
            "support_level":         self.support_level,
            "resistance_level":      self.resistance_level,
            "last_golden_cross_time":self.last_golden_cross_time,
            "last_death_cross_time": self.last_death_cross_time,
            "current_position_qty":  current_position_qty,
            "current_hedge_ratio":   round(current_hedge_ratio, 4),
        }
        try:
            with open(self._STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"[STATE] save_state failed: {e}")

    def restore_state(self):
        """
        โหลด state.json และ restore ค่าลงใน instance variables
        เรียกตอน startup ก่อน main loop
        ถ้าไม่มีไฟล์ → เริ่มจาก INITIALIZED ตามปกติ
        """
        if not os.path.exists(self._STATE_FILE):
            print("📂 [STATE] ไม่พบ state.json — เริ่มจาก INITIALIZED")
            return

        try:
            with open(self._STATE_FILE, "r", encoding="utf-8") as f:
                snap = json.load(f)

            self.bot_state             = snap.get("bot_state", STATE_INITIALIZED)
            self.support_level         = snap.get("support_level")
            self.resistance_level      = snap.get("resistance_level")
            self.last_golden_cross_time= snap.get("last_golden_cross_time")
            self.last_death_cross_time = snap.get("last_death_cross_time")

            restored_qty   = snap.get("current_position_qty", 0)
            restored_ratio = snap.get("current_hedge_ratio", 0.0)
            ts             = snap.get("timestamp", "unknown")

            msg = (f"[STATE] Restored from state.json | "
                   f"timestamp={ts} | state={self.bot_state} | "
                   f"position_qty={restored_qty} | hedge_ratio={restored_ratio}% | "
                   f"long_sl={self.support_level} | short_sl={self.resistance_level}")
            print(f"✅ {msg}")
            self.logger.state_change("STARTUP", self.bot_state, f"restored from snapshot ({ts})")

        except Exception as e:
            msg = f"[STATE] restore_state failed: {e} — เริ่มจาก INITIALIZED"
            print(f"⚠️ {msg}")
            self.logger.error(msg)

    def calculate_ma(self, prices, ma_type, length):
        if len(prices) < length: return None
        if ma_type == "SMA": return sum(prices[-length:]) / length
        elif ma_type == "EMA":
            alpha = 2 / (length + 1)
            ema = sum(prices[:length]) / length 
            for p in prices[length:]: ema = (p * alpha) + (ema * (1 - alpha))
            return ema
        elif ma_type == "WMA":
            weights = range(1, length + 1)
            return sum(p * w for p, w in zip(prices[-length:], weights)) / sum(weights)
        return None

    def display_market_table(self, data_points, tick_size=0.5):
        """แสดงตาราง Market Data สำหรับ T-0, T-1, T-2"""
        print("\n" + "="*140)
        print("📊 Market Data & Indicators (Last 3 Periods)")
        print("-"*140)
        
        # Header
        headers = ["Period", "Time", "Open", "High", "Low", "Close", "MA", "Upper", "Lower", "Support", "Resistance"]
        col_widths = [8, 16, 12, 12, 12, 12, 12, 12, 12, 12, 12]
        
        # Print header
        header_line = ""
        for h, w in zip(headers, col_widths):
            header_line += f"{h:^{w}}"
        print(header_line)
        print("-"*140)
        
        # Determine decimal places from tick_size
        if tick_size >= 1:
            decimal_places = 2
        elif tick_size >= 0.1:
            decimal_places = 2
        elif tick_size >= 0.01:
            decimal_places = 2
        else:
            # For very small tick sizes like 0.5 or 0.05
            decimal_places = max(2, len(str(tick_size).rstrip('0').split('.')[-1]))
        
        # Print data rows (T-0, T-1, T-2)
        period_labels = ["T-0", "T-1", "T-2"]
        for i, label in enumerate(period_labels):
            d = data_points[i] if i < len(data_points) else None
            
            if d:
                row = [
                    f"{label:^8}",
                    f"{d['time']:^16}",
                    f"{d['open']:>{12}.{decimal_places}f}",
                    f"{d['high']:>{12}.{decimal_places}f}",
                    f"{d['low']:>{12}.{decimal_places}f}",
                    f"{d['close']:>{12}.{decimal_places}f}",
                    f"{d['ma']:>{12}.{decimal_places}f}" if d['ma'] else f"{'N/A':>12}",
                    f"{d['up']:>{12}.{decimal_places}f}" if d['up'] else f"{'N/A':>12}",
                    f"{d['lo']:>{12}.{decimal_places}f}" if d['lo'] else f"{'N/A':>12}",
                ]
                
                # Support/Resistance ขึ้นอยู่กับ Period
                if i == 0:  # T-0 แสดงค่าปัจจุบัน
                    support_val = f"{self.support_level:>{12}.{decimal_places}f}" if self.support_level else f"{'N/A':>12}"
                    resistance_val = f"{self.resistance_level:>{12}.{decimal_places}f}" if self.resistance_level else f"{'N/A':>12}"
                else:  # T-1, T-2 แสดง N/A (เพราะเป็นอดีต)
                    support_val = f"{'N/A':>12}"
                    resistance_val = f"{'N/A':>12}"
                
                row.append(support_val)
                row.append(resistance_val)
                
                print("".join(row))
            else:
                # ถ้าไม่มีข้อมูล
                print(f"{label:^8}{'N/A':^16}{'N/A':>12}{'N/A':>12}{'N/A':>12}{'N/A':>12}{'N/A':>12}{'N/A':>12}{'N/A':>12}{'N/A':>12}{'N/A':>12}")
        
        print("="*140)
    
    def display_asset_breakdown(self, equity_futures, cold_storage_btc, current_price, currency_symbol="BTC"):
        """แสดง Asset Breakdown แยก Futures Account และ Cold Storage"""
        print("\n" + "="*75)
        print(f"💰 {currency_symbol} Balance Breakdown")
        print("-"*75)
        
        futures_usd = equity_futures * current_price
        cold_usd = cold_storage_btc * current_price
        total_btc = equity_futures + cold_storage_btc
        total_usd = futures_usd + cold_usd
        
        print(f"  Futures Account : {equity_futures:>12.8f} {currency_symbol}  (${futures_usd:>14,.2f} USD)")
        print(f"  Cold Storage    : {cold_storage_btc:>12.8f} {currency_symbol}  (${cold_usd:>14,.2f} USD)")
        print("-"*75)
        print(f"  Total Assets    : {total_btc:>12.8f} {currency_symbol}  (${total_usd:>14,.2f} USD)")
        print("="*75)
    
    def calculate_volatility(self, klines_slice, calc_type, length):
        if len(klines_slice) < length: return 0
        closes = [float(k[4]) for k in klines_slice]
        highs = [float(k[2]) for k in klines_slice]
        lows = [float(k[3]) for k in klines_slice]
        
        if calc_type == "SD":
            mean = sum(closes[-length:]) / length
            return math.sqrt(sum((x - mean) ** 2 for x in closes[-length:]) / length)
        elif calc_type == "ATR":
            tr_list = []
            for i in range(len(klines_slice)):
                h, l = highs[i], lows[i]
                if i == 0: tr_list.append(h - l)
                else:
                    pc = float(klines_slice[i-1][4])
                    tr_list.append(max(h - l, abs(h - pc), abs(l - pc)))
            return sum(tr_list[-length:]) / length
        elif calc_type == "TR":
            h, l = highs[-1], lows[-1]
            pc = float(klines_slice[-2][4]) if len(klines_slice) > 1 else l
            return max(h - l, abs(h - pc), abs(l - pc))
        elif calc_type == "RANGE":
            return sum((h - l) for h, l in zip(highs[-length:], lows[-length:])) / length
        return 0

    def execute_action(self, target_ratio, current_ratio, deviation_limit, total_usd, current_price, current_position_qty=0, execute_order=False, reason="rebalance", futures_usd=0.0):
        """
        คำนวณ Hedge Status และแสดงผล พร้อมเตรียมพร้อมสำหรับยิงออเดอร์จริง
        
        Parameters:
        - target_ratio: Hedge Ratio เป้าหมาย (%)
        - current_ratio: Hedge Ratio ปัจจุบัน (%)
        - deviation_limit: ค่า Deviation ที่ยอมรับได้ (%)
        - total_usd: มูลค่าพอร์ตรวม (USD)
        - current_price: ราคา BTC ปัจจุบัน
        - current_position_qty: จำนวน Contract ปัจจุบัน
        - execute_order: True = ยิงออเดอร์จริง, False = แสดงผลอย่างเดียว (Virtual Mode)
        - reason: สาเหตุ order เช่น "rebalance_neutral", "rebalance_long", "rebalance_short"
        - futures_usd: มูลค่า futures account (USD) สำหรับ CSV
        
        Returns: dict ข้อมูล Hedge Status
        """
        # 1. คำนวณมูลค่า Position ที่ต้องการ (USD)
        target_position_value_usd = total_usd * (target_ratio / 100.0)
        current_position_value_usd = total_usd * (current_ratio / 100.0)
        
        # 2. หาส่วนต่าง (Deviation)
        deviation_pct = target_ratio - current_ratio
        position_diff_usd = target_position_value_usd - current_position_value_usd
        
        # 3. คำนวณจำนวน Contract (สำหรับ XBTUSDM: 1 Contract = 1 USD)
        contracts_needed = int(abs(position_diff_usd))
        
        # 4. กำหนด Action
        if position_diff_usd > 0:
            action = "Open"
            contracts_action = f"Open {contracts_needed} Short"
        elif position_diff_usd < 0:
            action = "Close"
            contracts_action = f"Close {contracts_needed} Short"
        else:
            action = "None"
            contracts_action = "No action needed"
        
        # 5. คำนวณ Target Total Contracts
        target_total_contracts = int(abs(target_position_value_usd))
        
        # 6. แสดงผล Hedge Status (แบบกระชับ)
        print(f"\n📊 Hedge Status: Current {current_ratio:.2f}% | Target {target_ratio:.2f}% | Deviation: {deviation_pct:+.2f}%")
        
        rebalance_needed = abs(deviation_pct) > deviation_limit
        
        if rebalance_needed:
            print(f"📌 Action Required: {contracts_action} (Target total {target_total_contracts} contracts)")
            
            # 7. Execute Order (ถ้า execute_order=True)
            if execute_order:
                if action == "Open":
                    # เปิด Short = Sell
                    self.place_market_order(
                        side="sell", size=contracts_needed, reason=reason,
                        total_usd=total_usd, futures_usd=futures_usd, mid_price=current_price,
                        current_position_qty=current_position_qty
                    )
                elif action == "Close":
                    # ปิด Short = Buy
                    self.place_market_order(
                        side="buy", size=contracts_needed, reason=reason,
                        total_usd=total_usd, futures_usd=futures_usd, mid_price=current_price,
                        current_position_qty=current_position_qty
                    )
        else:
            print(f"✅ Within deviation limit ({deviation_limit}%) - No rebalance needed")
        
        # 8. Return ข้อมูลสำหรับใช้ในส่วนอื่นๆ
        return {
            "action": action,
            "contracts_needed": contracts_needed,
            "target_total_contracts": target_total_contracts,
            "deviation_pct": deviation_pct,
            "rebalance_needed": rebalance_needed,
            "position_diff_usd": position_diff_usd
        }

    def run_bot(self):
        print(f"🚀 บอทเริ่มทำงาน: {self.symbol}")
        
        # ดึง Contract Info เพื่อหา Multiplier 
        c_info = self.get_contract_info()
        if c_info and 'multiplier' in c_info:
            self.contract_multiplier = float(c_info['multiplier'])
            print(f"📦 Contract Size: {self.contract_multiplier} USD/Contact")

        # ดึง Account Config (marginMode, positionMode, leverage)
        self._fetch_account_config()

        # Restore state จาก snapshot ถ้ามี (หลัง restart)
        self.restore_state()

        print(f"⚙️ Timeframe: {self.timeframe}m | MA: {self.ma_type}({self.ma_length}) | Band: {self.band_calc}({self.band_length}) x{self.band_mult}")

        # รอให้ Websocket พร้อมก่อนเริ่ม loop (max 15 วินาที)
        print("⏳ รอ Websocket เชื่อมต่อ...")
        for _ in range(15):
            if self.ws_data["ws_connected"]:
                break
            time.sleep(1)
        
        if not self.ws_data["ws_connected"]:
            print("⚠️ [WS] Websocket ไม่พร้อมภายใน 15 วินาที — bot เริ่มทำงานด้วย REST ชั่วคราว")
        
        while True:
            try:
                # --- หยุดรอถ้า Websocket หลุด (disconnect) ---
                if not self.ws_data["ws_connected"]:
                    print("🔴 [WS] Websocket ไม่ได้เชื่อมต่อ — หยุดรอ reconnect...")
                    while not self.ws_data["ws_connected"]:
                        time.sleep(2)
                    print("✅ [WS] Websocket กลับมาแล้ว — เริ่ม loop ต่อ")

                currency_raw = self.symbol.split('USD')[0]
                currency_api = "XBT" if currency_raw in ["XBT", "BTC"] else currency_raw
                
                balance_data = self.get_futures_balance(currency_api)
                pos_list = self.get_active_position()
                klines_raw = self.get_kline_data()

                # --- ดึง Price จาก Websocket (แทน REST ticker) ---
                best_bid   = self.ws_data["best_bid"]
                best_ask   = self.ws_data["best_ask"]
                mid_price  = self.ws_data["mid_price"]

                # Fallback: ถ้า WS ยังไม่มีข้อมูล ดึงจาก REST แทน
                if mid_price == 0:
                    print("⚠️ [WS] ยังไม่มีข้อมูล WS — ใช้ REST ticker ชั่วคราว")
                    ticker = self.get_ticker_price()
                    if ticker:
                        best_bid  = float(ticker.get('bestBidPrice', 0))
                        best_ask  = float(ticker.get('bestAskPrice', 0))
                        mid_price = float(ticker.get('price', 0))

                # ใช้ mid_price เป็น current_price หลัก
                current_price = mid_price
                
                if balance_data and current_price > 0 and klines_raw:
                    
                    # --- 1. Virtual Stop Loss Check ---
                    sl_triggered = False
                    if self.bot_state == STATE_ENTERED_LONG and self.support_level:
                        if best_bid < self.support_level:
                            print(f"\n⚠️ [STOP LOSS] Bid ({best_bid:,.2f}) หลุด Long SL ({self.support_level:,.2f})!")
                            print("🔄 เปลี่ยนสถานะกลับเป็น INITIALIZED ทันที")
                            self.logger.state_change(
                                STATE_ENTERED_LONG, STATE_INITIALIZED,
                                f"stop_loss | bid={best_bid:,.2f} < sl={self.support_level:,.2f}"
                            )
                            self.bot_state = STATE_INITIALIZED
                            sl_triggered = True
                    
                    elif self.bot_state == STATE_ENTERED_SHORT and self.resistance_level:
                        if best_ask > self.resistance_level:
                            print(f"\n⚠️ [STOP LOSS] Ask ({best_ask:,.2f}) ทะลุ Short SL ({self.resistance_level:,.2f})!")
                            print("🔄 เปลี่ยนสถานะกลับเป็น INITIALIZED ทันที")
                            self.logger.state_change(
                                STATE_ENTERED_SHORT, STATE_INITIALIZED,
                                f"stop_loss | ask={best_ask:,.2f} > sl={self.resistance_level:,.2f}"
                            )
                            self.bot_state = STATE_INITIALIZED
                            sl_triggered = True

                    # --- 2. Indicators & Cross Detection ---
                    klines = sorted(klines_raw, key=lambda x: int(x[0]))
                    close_prices = [float(k[4]) for k in klines]
                    
                    data_points = []
                    for i in range(4): 
                        idx_end = len(klines) - i
                        if idx_end >= max(self.ma_length, self.band_length) + 1:
                            k_slice = klines[:idx_end]
                            p_slice = close_prices[:idx_end]
                            ma_val = self.calculate_ma(p_slice, self.ma_type, self.ma_length)
                            vol = self.calculate_volatility(k_slice, self.band_calc, self.band_length)
                            upper = ma_val + (self.band_mult * vol) if ma_val else None
                            lower = ma_val - (self.band_mult * vol) if ma_val else None
                            
                            # เก็บ OHLC ของแท่งนั้นๆ
                            last_candle = k_slice[-1]
                            data_points.append({
                                "ts":   int(last_candle[0]),   # raw timestamp (ms) สำหรับ cross dedup
                                "time": datetime.fromtimestamp(int(last_candle[0])/1000).strftime('%Y-%m-%d %H:%M'),
                                "open": float(last_candle[1]),
                                "high": float(last_candle[2]),
                                "low":  float(last_candle[3]),
                                "close":float(last_candle[4]),
                                "ma": ma_val, 
                                "up": upper, 
                                "lo": lower
                            })
                        else:
                            data_points.append(None)

                    # Print Header
                    print("\n" + "="*75)
                    ws_tag = "🟢 WS" if self.ws_data["ws_connected"] else "🟡 REST"
                    print(f"⏰ {datetime.now().strftime('%H:%M:%S')} | State: [{self.bot_state}] | Price Source: {ws_tag}")
                    print(f"🪙 {currency_raw} Mid: ${current_price:,.2f} | Bid: ${best_bid:,.2f} | Ask: ${best_ask:,.2f}")

                    # Cross Check
                    t1, t2 = data_points[1], data_points[2]
                    cross_occurred = False
                    
                    if not sl_triggered and t1 and t2:
                        if t1['up'] and t2['up']:
                            if (t1['close'] > t1['up'] and t2['close'] < t2['up']
                                    and self.bot_state != STATE_ENTERED_LONG
                                    and t1['ts'] != self.last_golden_cross_time):
                                print("🌟 [SIGNAL] GOLDEN CROSS Detected! -> Entering LONG State")
                                self.logger.state_change(
                                    self.bot_state, STATE_ENTERED_LONG,
                                    f"golden_cross | close={t1['close']:,.2f} > upper={t1['up']:,.2f}"
                                )
                                self.last_golden_cross_time = t1['ts']  # บันทึก candle ที่ trigger
                                self.bot_state = STATE_ENTERED_LONG
                                self.support_level = t1['lo']
                                print(f"📍 New Long SL Level: {self.support_level:,.2f}")
                                cross_occurred = True
                        
                        if t1['lo'] and t2['lo']:
                            if (t1['close'] < t1['lo'] and t2['close'] > t2['lo']
                                    and self.bot_state != STATE_ENTERED_SHORT
                                    and t1['ts'] != self.last_death_cross_time):
                                print("💀 [SIGNAL] DEATH CROSS Detected! -> Entering SHORT State")
                                self.logger.state_change(
                                    self.bot_state, STATE_ENTERED_SHORT,
                                    f"death_cross | close={t1['close']:,.2f} < lower={t1['lo']:,.2f}"
                                )
                                self.last_death_cross_time = t1['ts']  # บันทึก candle ที่ trigger
                                self.bot_state = STATE_ENTERED_SHORT
                                self.resistance_level = t1['up']
                                print(f"📍 New Short SL Level: {self.resistance_level:,.2f}")
                                cross_occurred = True

                    # --- 3. Spread Check ---
                    spread_pct = ((best_ask - best_bid) / best_bid) * 100 if best_bid > 0 else 0
                    spread_safe = spread_pct <= self.max_spread_pct

                    # --- 4. Portfolio & Hedge Ratio Calculation ---
                    equity_f = float(balance_data.get('accountEquity', 0))
                    total_usd = (equity_f + self.cold_storage_amount) * current_price
                    
                    current_hedge_ratio = 0
                    pos_val_usd = 0
                    if pos_list and len(pos_list) > 0:
                        pos = pos_list[0]
                        qty = int(pos.get('currentQty', 0))
                        if pos.get('isOpen') and abs(qty) > 0:
                            p_side = str(pos.get('positionSide', '')).upper()
                            if p_side == "BOTH": p_side = "SHORT" if qty < 0 else "LONG"
                            pos_val_usd = abs(float(pos.get('markValue', 0))) * current_price
                            if p_side == 'SHORT':
                                current_hedge_ratio = (pos_val_usd / total_usd) * 100 if total_usd > 0 else 0

                    # --- 5. Action / Execution Logic ---
                    # บอทจะออก Action เมื่อมีการชน SL, มี Cross ใหม่, หรือถึงรอบ Rebalance ปกติ
                    if not spread_safe:
                        msg = f"Spread กว้างเกินไป ({spread_pct:.3f}% > {self.max_spread_pct}%) ข้ามการออกออเดอร์"
                        print(f"🚧 {msg}")
                        self.logger.warning(f"[SPREAD] {msg}")
                    else:
                        # ดึงจำนวน Contract ปัจจุบัน (ถ้ามี Position)
                        current_position_qty = 0
                        if pos_list and len(pos_list) > 0:
                            pos = pos_list[0]
                            if pos.get('isOpen'):
                                current_position_qty = int(pos.get('currentQty', 0))

                        futures_usd = equity_f * current_price

                        if self.bot_state == STATE_INITIALIZED:
                            self.execute_action(
                                self.neutral_hedge_pct, 
                                current_hedge_ratio, 
                                self.neutral_dev_limit, 
                                total_usd, 
                                current_price,
                                current_position_qty,
                                execute_order=True,
                                reason="rebalance_neutral",
                                futures_usd=futures_usd
                            )
                        
                        elif self.bot_state == STATE_ENTERED_SHORT:
                            self.execute_action(
                                self.short_hedge_target, 
                                current_hedge_ratio, 
                                self.short_dev_limit, 
                                total_usd, 
                                current_price,
                                current_position_qty,
                                execute_order=True,
                                reason="rebalance_short",
                                futures_usd=futures_usd
                            )
                        
                        elif self.bot_state == STATE_ENTERED_LONG:
                            if self.long_mode == "rebalance":
                                self.execute_action(
                                    self.long_hedge_target, 
                                    current_hedge_ratio, 
                                    self.long_dev_limit, 
                                    total_usd, 
                                    current_price,
                                    current_position_qty,
                                    execute_order=True,
                                    reason="rebalance_long",
                                    futures_usd=futures_usd
                                )
                            
                            elif self.long_mode == "rpt" and cross_occurred:
                                if self.support_level and current_price > self.support_level:
                                    risk_amount_usd = total_usd * (self.long_rpt_pct / 100.0)
                                    sl_distance = current_price - self.support_level
                                    target_contracts = int((risk_amount_usd * current_price) / (sl_distance * abs(self.contract_multiplier)))
                                    print(f"🛠️ [ACTION-RPT] Market Buy ปิด Short จำนวน {target_contracts} contracts")
                                    print(f"    (Risk: ${risk_amount_usd:,.2f} | SL Dist: {sl_distance:,.2f})")
                                    self.place_market_order(
                                        side="buy", size=target_contracts,
                                        reason="enter_long_rpt",
                                        total_usd=total_usd, futures_usd=futures_usd,
                                        mid_price=current_price,
                                        current_position_qty=current_position_qty
                                    )

                    # --- Display Console ---
                    # 1. ดึง tickSize จาก contract info
                    c_info = self.get_contract_info()
                    tick_size = float(c_info.get('tickSize', 0.5)) if c_info else 0.5
                    
                    # 2. แสดงตาราง Market Data
                    self.display_market_table(data_points, tick_size)
                    
                    # 3. แสดง Asset Breakdown
                    self.display_asset_breakdown(equity_f, self.cold_storage_amount, current_price, currency_raw)
                    
                    # 4. ดึง Liquidation Price จาก position ปัจจุบัน
                    liq_price = None
                    if pos_list and len(pos_list) > 0:
                        pos = pos_list[0]
                        if pos.get('isOpen'):
                            liq_raw = pos.get('liquidationPrice')
                            if liq_raw is not None:
                                liq_val = float(liq_raw)
                                # liq price = 0.01 หมายถึง CROSS margin ที่ไม่มี hard liq price
                                liq_price = liq_val if liq_val > 1 else None

                    # 5. แสดง Hedge Ratio, Stop Loss และ Liquidation Price
                    print(f"\n📉 Current Hedge Ratio: {current_hedge_ratio:.2f}%")
                    print(f"🟢 Long SL: {f'${self.support_level:,.2f}' if self.support_level else 'N/A'} | 🔴 Short SL: {f'${self.resistance_level:,.2f}' if self.resistance_level else 'N/A'}")
                    if liq_price:
                        print(f"🔥 Liq Price: ${liq_price:,.2f} ({self.margin_mode})")
                    else:
                        print(f"🔥 Liq Price: N/A {'(CROSS — risk-rate based)' if self.margin_mode == 'CROSS' else '(ยังไม่มี position)'}")
                    print("="*75)

                    # 6. บันทึก state snapshot ทุก loop (overwrite — เก็บแค่ล่าสุด)
                    self.save_state(
                        current_hedge_ratio=current_hedge_ratio,
                        current_position_qty=current_position_qty
                    )

                    # หากชน SL ในลูปนี้ ให้ข้ามการ Sleep เพื่อไปประมวลผล Rebalance ในวินาทีถัดไปทันที
                    if sl_triggered:
                        continue

            except Exception as e:
                msg = f"Main loop exception: {e}"
                print(f"⚠️ Error: {e}")
                self.logger.error(f"[LOOP] {msg}")
            
            time.sleep(self.interval)

if __name__ == "__main__":
    config_path = "config.json"
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            bot = KuCoinBot(json.load(f))
            bot.run_bot()
    else:
        print("❌ ไม่พบไฟล์ config.json")