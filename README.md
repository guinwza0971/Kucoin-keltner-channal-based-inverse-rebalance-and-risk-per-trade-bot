# KuCoin Futures Hedge Bot 🚀

บอทเทรดอัตโนมัติสำหรับ KuCoin Futures ที่ออกแบบมาเพื่อการบริหารความเสี่ยง (Hedging) โดยเฉพาะ รองรับการคำนวณสัดส่วนการถือครองให้สัมพันธ์กับสินทรัพย์ใน Cold Storage และการเข้าเทรดด้วยสัญญาณทางเทคนิค

## 🛠 Features

* **Real-time Monitoring**: ใช้ **Public WebSocket** ในการดึงราคา Bid/Ask/Mid Price เพื่อความรวดเร็วและแม่นยำสูงกว่า REST API
* **Dynamic Indicators**: รองรับการคำนวณ Moving Average (SMA, EMA, WMA) และ Volatility Band (Bollinger Bands) แบบปรับแต่งได้
* **Hedge Management**: คำนวณ Net Exposure ของพอร์ตโดยรวม (Futures Account + Cold Storage) เพื่อรักษา Hedge Ratio ที่กำหนด
* **Flexible Strategy**:
    * **Golden/Death Cross**: เข้าสถานะตามการตัดกันของราคากับ Indicator
    * **Risk Per Trade (RPT)**: คำนวณจำนวน Contract ตามความเสี่ยง (Position Sizing) เมื่อเกิดสัญญาณ Long
    * **Virtual Stop Loss**: ระบบตัดขาดทุนอัจฉริยะที่ติดตามราคาจาก WebSocket ตลอดเวลา
* **Robust Logging**: ระบบบันทึก `bot.log` แบบ Rotating (ไม่เปลืองพื้นที่) และ `tradehistory.csv` สำหรับการทำบัญชีเทรด
* **State Persistence**: บันทึกสถานะล่าสุดลง `state.json` ช่วยให้บอททำงานต่อได้ทันทีหลัง Restart โดยไม่เสียตำแหน่งสัญญาณเดิม
* **Self-Managed SSL**: ระบบ Auto-refresh `cacert.pem` แก้ปัญหา SSL Certificate บน Windows/VPS

## 📋 Requirement

* Python 3.8+
* KuCoin Futures API Key (Trade, General permission)
* Dependencies:
    ```bash
    pip install requests websocket-client certifi
    ```

## ⚙️ Configuration (config.json)

สร้างไฟล์ `config.json` ไว้ในโฟลเดอร์เดียวกับบอท:

```json
{
  "api_key": "YOUR_API_KEY",
  "api_secret": "YOUR_API_SECRET",
  "api_passphrase": "YOUR_PASSPHRASE",
  "symbol": "XBTUSDM",
  "cold_storage_amount": 0.5,
  "leverage": 1,
  "ma_type": "EMA",
  "ma_length": 30,
  "band_multiplier": 1.0,
  "neutral_hedge_pct": 100.0,
  "use_test_endpoint": true
}
