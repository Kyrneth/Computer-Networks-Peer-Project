from scapy.all import sniff, TCP, IP
from collections import defaultdict, deque
import time

# Track SYN packets per IP in a sliding window
syn_history = defaultdict(deque)

THRESHOLD = 50          # SYN packets allowed in the window
WINDOW_SECONDS = 10     # Sliding window size

def detect_syn_flood(packet):
    # Only inspect TCP packets with SYN flag set and ACK flag NOT set
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        ip = packet[IP]

        # SYN-only packets (SYN=1, ACK=0)
        if tcp.flags == "S":
            src = ip.src
            now = time.time()

            # Add timestamp of this SYN packet
            syn_history[src].append(now)

            # Remove timestamps older than WINDOW_SECONDS
            while syn_history[src] and now - syn_history[src][0] > WINDOW_SECONDS:
                syn_history[src].popleft()

            # Check threshold
            if len(syn_history[src]) > THRESHOLD:
                print(f"\n⚠️ ALERT: Possible SYN Flood detected from {src}")
                print(f"   Count: {len(syn_history[src])} SYN packets in {WINDOW_SECONDS} seconds\n")

def main():
    print("Starting SYN flood detector...")
    sniff(filter="tcp", prn=detect_syn_flood, store=False)

if __name__ == "__main__":
    main()
