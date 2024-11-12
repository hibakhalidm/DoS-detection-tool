# src/capture/packet_sniffer.py
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from datetime import datetime
import threading
import time

# Global storage for captured packets
traffic_data = pd.DataFrame(columns=['timestamp', 'protocol', 'src_ip', 'dst_ip', 'pkt_size', 'flags'])

def packet_callback(packet):
    if packet.haslayer(IP):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        protocol = packet[IP].proto
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_size = len(packet)

        # Capture TCP flags if it's a TCP packet
        flags = None
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
        elif packet.haslayer(UDP):
            flags = "UDP"

        # Store packet data
        traffic_data.loc[len(traffic_data)] = [timestamp, protocol, src_ip, dst_ip, pkt_size, flags]
        print(f"[{timestamp}] Protocol: {protocol}, Source: {src_ip}, Destination: {dst_ip}, Size: {pkt_size}, Flags: {flags}")

def start_sniffing(count=100):
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, count=count)

def display_statistics(interval=5):
    """Display real-time packet statistics every 'interval' seconds."""
    while True:
        time.sleep(interval)
        total_packets = len(traffic_data)
        print(f"Total packets captured: {total_packets}")

def run_sniffer(count=100, stats_interval=5):
    # Start the statistics display in a separate thread
    stats_thread = threading.Thread(target=display_statistics, args=(stats_interval,))
    stats_thread.daemon = True
    stats_thread.start()

    start_sniffing(count)

    # Save the captured data to CSV after sniffing is done
    traffic_data.to_csv("../data/raw/captured_traffic.csv", index=False)
    print("Data saved to captured_traffic.csv")

if __name__ == "__main__":
    run_sniffer(count=100)
