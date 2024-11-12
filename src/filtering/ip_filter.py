# src/filtering/ip_filter.py
from collections import defaultdict
from datetime import datetime
from src.utils.detection_log import log_detection

THRESHOLD_RATE = 100
blacklist = set()
ip_packet_counts = defaultdict(int)

def check_and_filter_ip(src_ip):
    ip_packet_counts[src_ip] += 1

    if ip_packet_counts[src_ip] > THRESHOLD_RATE:
        blacklist.add(src_ip)
        log_detection(src_ip, ip_packet_counts[src_ip])
        print(f"IP {src_ip} blacklisted")
        return True
    return False
