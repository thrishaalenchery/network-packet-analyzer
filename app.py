import time
import threading
import random
from datetime import datetime
from flask import Flask, render_template, jsonify, request

# Import Scapy cleanly with error protection
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"[Warning] Scapy import exception: {e}")

app = Flask(__name__)

# State Management
packets_lock = threading.Lock()
captured_packets = []
packet_id_counter = 0

is_capturing = False
is_demo_mode = False
capture_error_msg = None

sniff_thread = None
demo_thread = None

# Statistics Counters
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0
}

# History for timeline chart (packets per second / interval)
time_series_data = []

def parse_scapy_packet(packet):
    """Parses a Scapy packet into a structured dictionary for presentation."""
    global packet_id_counter, stats
    
    with packets_lock:
        packet_id_counter += 1
        pkt_id = packet_id_counter
        
        # Determine Timestamp
        pkt_time = datetime.now().strftime("%H:%M:%S")
        timestamp_epoch = time.time()
        
        # Protocol & Addressing
        src_ip = "N/A"
        dst_ip = "N/A"
        protocol = "Other"
        src_port = "-"
        dst_port = "-"
        length = len(packet)
        details = {}
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            details["IP Version"] = "IPv4"
            details["TTL"] = packet[IP].ttl
            details["Header Length"] = f"{packet[IP].ihl * 4} bytes"
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            details["IP Version"] = "IPv6"
        elif packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            protocol = "Other"
            details["Type"] = "ARP Request/Reply"
            
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = str(packet[TCP].sport)
            dst_port = str(packet[TCP].dport)
            details["Source Port"] = src_port
            details["Destination Port"] = dst_port
            details["Sequence Number"] = packet[TCP].seq
            details["Acknowledgment"] = packet[TCP].ack
            details["Flags"] = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = str(packet[UDP].sport)
            dst_port = str(packet[UDP].dport)
            details["Source Port"] = src_port
            details["Destination Port"] = dst_port
            details["Length"] = packet[UDP].len
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            details["Type"] = packet[ICMP].type
            details["Code"] = packet[ICMP].code

        # Check payload
        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load
            # Hex snippet preview
            details["Payload Preview (Hex)"] = raw_payload[:32].hex()
            # ASCII preview if printable
            ascii_preview = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_payload[:64]])
            details["Payload Preview (ASCII)"] = ascii_preview

        # Update stats
        stats["total"] += 1
        if protocol == "TCP":
            stats["tcp"] += 1
        elif protocol == "UDP":
            stats["udp"] += 1
        elif protocol == "ICMP":
            stats["icmp"] += 1
        else:
            stats["other"] += 1

        pkt_record = {
            "id": pkt_id,
            "time": pkt_time,
            "timestamp": timestamp_epoch,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "summary": packet.summary(),
            "details": details
        }
        
        captured_packets.append(pkt_record)
        # Keep maximum 1000 packets in memory
        if len(captured_packets) > 1000:
            captured_packets.pop(0)

def real_sniffer_worker():
    """Background worker for live packet capture using Scapy."""
    global is_capturing, capture_error_msg, is_demo_mode
    try:
        def pkt_callback(pkt):
            if not is_capturing:
                return False
            parse_scapy_packet(pkt)
            return None

        # Sniff packets continuously while is_capturing is True
        sniff(prn=pkt_callback, stop_filter=lambda p: not is_capturing, store=0)
    except Exception as e:
        print(f"[Error] Scapy sniffing failed: {e}")
        capture_error_msg = f"Live Capture Error: {str(e)}. (Ensure Npcap is installed and app is run as Administrator)"
        is_demo_mode = True
        # Fallback to demo generator thread if real sniffing fails
        run_demo_generator()

def generate_demo_packet():
    """Generates synthetic, realistic network packets for DEMO MODE."""
    global packet_id_counter, stats
    
    protocols = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "Other"]
    chosen_proto = random.choice(protocols)
    
    sample_ips = [
        "192.168.1.105", "192.168.1.1", "142.250.190.46", 
        "104.21.34.120", "1.1.1.1", "8.8.8.8", "172.217.16.206"
    ]
    
    src_ip = random.choice(sample_ips)
    dst_ip = random.choice([ip for ip in sample_ips if ip != src_ip])
    
    pkt_time = datetime.now().strftime("%H:%M:%S")
    timestamp_epoch = time.time()
    
    src_port = "-"
    dst_port = "-"
    length = random.randint(54, 1514)
    details = {"IP Version": "IPv4", "TTL": random.choice([64, 128, 56])}
    
    if chosen_proto == "TCP":
        common_ports = [("443", "HTTPS"), ("80", "HTTP"), ("22", "SSH"), ("53012", "Ephemeral")]
        s_p, _ = random.choice(common_ports)
        d_p, service = random.choice(common_ports)
        src_port = str(random.randint(49152, 65535)) if s_p == "53012" else s_p
        dst_port = d_p
        details["Source Port"] = src_port
        details["Destination Port"] = dst_port
        details["Service"] = service
        details["Flags"] = random.choice(["[SYN]", "[ACK]", "[PA]", "[FIN, ACK]"])
        details["Seq"] = random.randint(100000, 999999)
        summary = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} {details['Flags']} Len={length}"
    elif chosen_proto == "UDP":
        src_port = str(random.randint(49152, 65535))
        dst_port = str(random.choice([53, 123, 443]))
        details["Source Port"] = src_port
        details["Destination Port"] = dst_port
        details["Service"] = "DNS Domain Lookups" if dst_port == "53" else "UDP Datagram"
        summary = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} Len={length}"
    elif chosen_proto == "ICMP":
        details["Type"] = random.choice([8, 0])
        type_str = "Echo (ping) request" if details["Type"] == 8 else "Echo (ping) reply"
        details["Description"] = type_str
        summary = f"ICMP {src_ip} -> {dst_ip} {type_str} id=0x0001 seq={random.randint(1, 100)}"
    else:
        summary = f"ARP Who has {dst_ip}? Tell {src_ip}"
        details["Type"] = "ARP Protocol Broadcast"
        
    details["Payload Preview (ASCII)"] = "GET /index.html HTTP/1.1\\r\\nHost: example.com" if chosen_proto == "TCP" else "Standard network packet payload sample data"
    
    with packets_lock:
        packet_id_counter += 1
        pkt_id = packet_id_counter
        
        stats["total"] += 1
        if chosen_proto == "TCP":
            stats["tcp"] += 1
        elif chosen_proto == "UDP":
            stats["udp"] += 1
        elif chosen_proto == "ICMP":
            stats["icmp"] += 1
        else:
            stats["other"] += 1
            
        pkt_record = {
            "id": pkt_id,
            "time": pkt_time,
            "timestamp": timestamp_epoch,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": chosen_proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "summary": summary,
            "details": details
        }
        
        captured_packets.append(pkt_record)
        if len(captured_packets) > 1000:
            captured_packets.pop(0)

def demo_worker():
    """Background worker for demo packet generation."""
    global is_capturing, is_demo_mode
    while is_capturing and is_demo_mode:
        generate_demo_packet()
        time.sleep(random.uniform(0.3, 0.7))

def run_demo_generator():
    """Starts the demo generator worker thread."""
    global demo_thread
    demo_thread = threading.Thread(target=demo_worker, daemon=True)
    demo_thread.start()

# Flask Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "is_capturing": is_capturing,
        "is_demo_mode": is_demo_mode,
        "scapy_available": SCAPY_AVAILABLE,
        "capture_error": capture_error_msg,
        "total_packets": stats["total"]
    })

@app.route("/api/start", methods=["POST"])
def start_capture():
    global is_capturing, sniff_thread, is_demo_mode, capture_error_msg
    
    if not is_capturing:
        is_capturing = True
        capture_error_msg = None
        
        # Check if requested or if Scapy isn't available
        if request.json and request.json.get("demo_mode"):
            is_demo_mode = True
            run_demo_generator()
        elif SCAPY_AVAILABLE and not is_demo_mode:
            # Try launching real sniffer thread
            try:
                sniff_thread = threading.Thread(target=real_sniffer_worker, daemon=True)
                sniff_thread.start()
            except Exception as e:
                capture_error_msg = f"Failed to start packet capture thread: {e}"
                is_demo_mode = True
                run_demo_generator()
        else:
            is_demo_mode = True
            run_demo_generator()
            
    return jsonify({
        "status": "success",
        "is_capturing": is_capturing,
        "is_demo_mode": is_demo_mode,
        "capture_error": capture_error_msg
    })

@app.route("/api/stop", methods=["POST"])
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({"status": "success", "is_capturing": is_capturing})

@app.route("/api/clear", methods=["POST"])
def clear_data():
    global captured_packets, packet_id_counter, stats
    with packets_lock:
        captured_packets.clear()
        packet_id_counter = 0
        stats["total"] = 0
        stats["tcp"] = 0
        stats["udp"] = 0
        stats["icmp"] = 0
        stats["other"] = 0
    return jsonify({"status": "success"})

@app.route("/api/toggle_demo", methods=["POST"])
def toggle_demo():
    global is_demo_mode, is_capturing
    is_demo_mode = not is_demo_mode
    if is_capturing:
        # Restart worker
        if is_demo_mode:
            run_demo_generator()
        else:
            sniff_thread = threading.Thread(target=real_sniffer_worker, daemon=True)
            sniff_thread.start()
    return jsonify({"status": "success", "is_demo_mode": is_demo_mode})

@app.route("/api/packets", methods=["GET"])
def get_packets():
    with packets_lock:
        since_id = request.args.get("since_id", default=0, type=int)
        protocol = request.args.get("protocol", default="ALL", type=str).upper()
        ip_query = request.args.get("ip", default="", type=str).strip()
        port_query = request.args.get("port", default="", type=str).strip()
        
        filtered = [p for p in captured_packets if p["id"] > since_id]
        
        if protocol != "ALL":
            filtered = [p for p in filtered if p["protocol"] == protocol]
            
        if ip_query:
            filtered = [p for p in filtered if ip_query in p["src_ip"] or ip_query in p["dst_ip"]]
            
        if port_query:
            filtered = [p for p in filtered if port_query == str(p["src_port"]) or port_query == str(p["dst_port"])]
            
        return jsonify({
            "packets": filtered,
            "last_id": packet_id_counter
        })

@app.route("/api/stats", methods=["GET"])
def get_stats():
    with packets_lock:
        return jsonify(stats)

if __name__ == "__main__":
    print("==================================================")
    print("  NETWORK PACKET ANALYZER - Flask Server Starting ")
    print("  Open http://127.0.0.1:5000 in your browser     ")
    print("==================================================")
    app.run(host="0.0.0.0", port=5000, debug=False)
