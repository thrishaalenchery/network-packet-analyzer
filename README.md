# NETWORK PACKET ANALYZER
### Computer Networks – Activity 2 (Problem-Based Learning)

A complete, real-time web-based network packet monitoring and protocol analysis tool built for computer network demonstration and academic presentation.

---

## 📌 Project Objective
The goal of this project is to build an intuitive, web-based Network Packet Analyzer that captures real-time network traffic from system network interfaces using Python's **Scapy** library, performs protocol classification (TCP, UDP, ICMP, Other), extracts packet header fields, and visualizes packet traffic trends using **Chart.js** in a clean, black-and-white academic interface.

---

## 🛠️ Technologies Used
- **Backend:** Python 3, Flask (REST API)
- **Packet Capture Engine:** Scapy
- **Frontend:** HTML5, Vanilla CSS3 (Academic Monochrome Theme), JavaScript (ES6)
- **Analytics & Data Visualization:** Chart.js (CDN)

---

## ✨ Features
1. **Live Packet Dashboard:** Real-time Start, Stop, and Clear controls with status indicator (`LIVE CAPTURE ACTIVE` / `CAPTURE STOPPED`).
2. **Real Packet Capture Engine:** Sniffs network packets directly from host network interface using Scapy.
3. **Automatic Fallback & Demo Mode:** If Administrator privileges or Npcap drivers are missing, the system gracefully notifies the user and provides a seamless **DEMO MODE** for presentation.
4. **Live Packet Table:** Continuous updates displaying Packet ID, Timestamp, Source IP, Destination IP, Protocol, Source Port, Destination Port, and Packet Length.
5. **Interactive Packet Inspection Modal:** Click any packet row to open a full header inspector showing IP fields, transport ports, sequence numbers, flags, and hex/ASCII payload previews.
6. **Live Multi-Criteria Filtering:** Instantly filter captured packets by IP address, protocol (TCP / UDP / ICMP / Other), or port number.
7. **Real-time Analytics:** Visual protocol distribution doughnut chart and continuous packet throughput timeline line chart.

---

## 📂 Project Structure
```
network-packet-analyzer/
│
├── app.py                  # Flask web server & Scapy packet capture engine
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation & presentation script
├── templates/
│   └── index.html          # Academic monochrome HTML5 interface
└── static/
    ├── style.css           # Academic CSS design system
    └── script.js           # Polling engine, Chart.js integrations & modal logic
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+ installed
- Npcap driver installed on Windows (required for Scapy live capture): Download from [https://npcap.com/](https://npcap.com/)

### Step 1: Install Python Dependencies
Open PowerShell / Command Prompt in the project folder and run:
```bash
pip install -r requirements.txt
```

---

## 💻 How to Run the Application

### Option A: Standard Run (Standard Privileges / Demo Mode)
```bash
python app.py
```

### Option B: Run as Administrator (For Real Live Packet Capture on Windows)
To allow Scapy to access raw network sockets and sniff real network traffic on Windows, open PowerShell as **Administrator** and run:
```powershell
python app.py
```
Or directly from standard PowerShell:
```powershell
Start-Process python -ArgumentList 'app.py' -Verb RunAs
```

Once started, open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🎤 LIVE DEMO SCRIPT (Say this during your presentation!)

> *"Respected Teacher, today I am presenting our Computer Networks project titled **Network Packet Analyzer**. This application monitors real-time network traffic passing through the host machine's interface using Python's Scapy library. As I click **Start Capture**, the analyzer actively sniffs incoming and outgoing packets, classifying them into TCP, UDP, ICMP, or other protocols. When I generate traffic by pinging a server or opening a webpage, the live table populates instantaneously with IP addresses, port numbers, and packet sizes. I can click on any individual packet to inspect its full header fields, TCP flags, and payload preview in our detail modal. Finally, the built-in Chart.js visualizer gives us live analytics on protocol ratios and packet arrival rate over time."*

---

## 🔄 Live Presentation Demo Flow

```
   START APPLICATION (`python app.py`)
                 ↓
      OPEN DASHBOARD (`http://127.0.0.1:5000`)
                 ↓
       CLICK "START CAPTURE"
                 ↓
     GENERATE NETWORK TRAFFIC (ping / web browsing)
                 ↓
      PACKETS APPEAR LIVE IN TABLE
                 ↓
     FILTER BY PROTOCOL (TCP / UDP / ICMP)
                 ↓
      OPEN PACKET DETAILS MODAL
                 ↓
      SHOW REAL-TIME CHARTS
                 ↓
       CLICK "STOP CAPTURE"
```

---

## 🌐 How to Generate Network Traffic for Demo
While **LIVE CAPTURE ACTIVE** is enabled, open a terminal window and run any of the following commands to generate real network packets:

1. **ICMP Traffic (Ping):**
   ```bash
   ping 8.8.8.8
   ```
2. **DNS & UDP Traffic:**
   ```bash
   nslookup google.com
   ```
3. **HTTP / TCP Traffic:**
   Open any website in your web browser (e.g. `https://httpbin.org/get` or `google.com`), or run:
   ```bash
   curl -I https://www.google.com
   ```

---

## 📊 Expected Output
- **Dashboard Counters:** Live metrics incrementing automatically.
- **Packet Table:** Rows dynamically added showing packet headers.
- **Protocol Distribution:** Doughnut chart highlighting proportion of TCP vs UDP vs ICMP packets.
- **Timeline Chart:** Live line graph showing packet arrival rate per second.

---

### Project Info
- **Subject:** Computer Networks – Activity 2 (Problem-Based Learning)
- **Project Name:** Network Packet Analyzer
