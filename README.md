# Wi-Fi Deauthentication Attack Simulator

## 📌 Overview
This tool demonstrates **Wi-Fi deauthentication attacks**, detects malicious activity, and provides countermeasures to prevent such attacks. It can:
- **Simulate deauthentication attacks** by sending deauth packets
- **Detect ongoing deauth attacks** and log attackers
- **Automatically block attackers** using iptables
- **Prevent attacks** by maintaining Wi-Fi reassociation requests

## 🚀 Features
✔ **Deauthentication Attack Simulation** – Disconnects target devices from Wi-Fi networks  
✔ **Attack Detection & Logging** – Monitors for deauth packets and logs attackers  
✔ **Auto-Block Attackers** – Adds malicious devices to an iptables deny list  
✔ **Countermeasures** – Sends reassociation requests to maintain connection  
✔ **Logging** – Stores attack details in `deauth_attack_log.txt`

## 📦 Requirements
- **Python 3.x**
- **Root/Sudo Access** (for raw packet manipulation & iptables)
- **Wireless Network Adapter** supporting **monitor mode**

## 🛠 Installation
### **1️⃣ Install Dependencies**
```bash
pip install scapy
```

### **2️⃣ Enable Monitor Mode (Linux/macOS)**
```bash
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up
```
Replace `wlan0` with your actual **Wi-Fi interface name**.

## 🚀 Usage
### **Simulate a Deauthentication Attack**
```bash
sudo python wifi_deauth_simulator.py
```
- Select **Mode 1** (Simulate Attack)
- Enter the **Target MAC Address** and **AP MAC Address**
- Choose the **number of deauthentication packets** to send

### **Detect & Block Deauthentication Attacks**
```bash
sudo python wifi_deauth_simulator.py
```
- Select **Mode 2** (Detect Attack)
- The tool will log and **automatically block attackers**

### **Prevent Attacks (Countermeasure Mode)**
```bash
sudo python wifi_deauth_simulator.py
```
- Select **Mode 3** (Prevent Attack)
- The script will send reassociation requests to maintain Wi-Fi stability

## 📄 Logs & Block List
- **Deauthentication logs** are stored in `deauth_attack_log.txt`
- **Blocked attackers** are listed in `blocked_devices.txt`

## ⚠️ Disclaimer
This tool is for **educational and security research purposes only**. **Unauthorized use on external networks is illegal**. Ensure you have **explicit permission** before running this on any network.

🔒 **Stay ethical and secure!**

