import socket
import struct
import threading
import time
import netifaces


LIMIT_S = 500
LIMIT = 500
local_ip = None
mac_address = None

class IPAddressInfo:
    def __init__(self, ip):
        self.ip = ip
        self.count = 0
        self.notification_sent = False
        self.start_time = time.time()

    def increment_count(self):
        self.count += 1

    def reset_count(self):
        self.count = 0
        self.notification_sent = False
        self.start_time = time.time()

    def time_elapsed(self):
        return time.time() - self.start_time

http_requests = {} # store count of HTTP request per IP
syn_counters = {} # store SYN packet counters per IP

lock = threading.Lock() # Lock counter store to manage access

# store counts of other packet types
packet_counts = {
    "ARP Request": 0,
    "ARP Reply": 0,
    "IPv4": 0,
    "ICMP": 0,
    "IPv6": 0,
    "TCP": 0,
    "UDP": 0
}

def process_ipv4(data):
    packet_counts["IPv4"] += 1
    (data, src, target, proto) = ipv4_packet(data)
    print("IPv4 -> IP:", src)  # Print IP address source
    if proto == 1:
        packet_counts["ICMP"] += 1
        print("    ICMP (IPv4):")
    elif proto == 6:
        packet_counts["TCP"] += 1
        print("    TCP (IPv4):")
        if local_ip == target:
            tcp_data = tcp_segment(data)
            if tcp_data:
                src_port, dest_port, flags = tcp_data
                if flags & 0x02:  # check the SYN flag
                    process_syn_packet(src)
            handle_packet(data, src)
    elif proto == 17:
        packet_counts["UDP"] += 1
        print("    UDP (IPv4):")
        udp_datagram(data)


def process_arp(data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode, data = arp_packet(data)
    if opcode == 1:
        packet_counts["ARP Request"] += 1
        print("ARP Request -> MAC:", get_mac_addr(data[8:14]), "IP:", socket.inet_ntoa(data[14:18]))
    elif opcode == 2:
        packet_counts["ARP Reply"] += 1
        print("ARP Reply -> MAC:", get_mac_addr(data[8:14]), "IP:", socket.inet_ntoa(data[14:18]))

def process_ipv6(data):
    packet_counts["IPv6"] += 1
    (data, src, target, next_header) = ipv6_packet(data)
    print("IPv6 -> IP:", src)  # Print IP address source
    if next_header == 6:
        packet_counts["TCP (IPv6)"] += 1
        if local_ip == target:
            tcp_data = tcp_segment(data)
            print("    TCP (IPv6):")
            if tcp_data:
                src_port, dest_port, flags = tcp_data
                if flags & 0x02:  # check the SYN flag
                    process_syn_packet(src)
            handle_packet(data, src)
    elif next_header == 17:
        packet_counts["UDP (IPv6)"] += 1
        udp_datagram(data)
        print("    UDP (IPv6):")

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    _, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    # converting IP addresses to readable strings
    src_ip = socket.inet_ntoa(src)
    target_ip = socket.inet_ntoa(target)

    return data[header_length:], src_ip, target_ip, proto
            
def arp_packet(data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack('! H H B B H', data[:8])
    return hardware_type, protocol_type, hardware_size, protocol_size, opcode, data[8:]

def tcp_segment(data):
    try:
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 0x01FF
        return src_port, dest_port, flags
    except struct.error:
        return None

def udp_datagram(data):
    if len(data) > 8:
        src_port, dest_port, size = struct.unpack('! H H 2x', data[:8])
    else:
        print("Data is too short to unpack")
    return data[8:]  # Return data after UDP header
    return None

def ipv6_packet(data):
  
    version_traffic_class_flow_label, payload_length, next_header, hop_limit, src, target = struct.unpack('! 4s H B B 16s 16s', data[:40])
    # converting IP addresses to readable string
    src_addr = socket.inet_ntop(socket.AF_INET6, src)
    target_addr = socket.inet_ntop(socket.AF_INET6, target)
    return data[40:], src_addr, target_addr, next_header


# Control variable to track if notif has been sent within the last ten seconds
notification_sent = False

def process_syn_packet(src):
    with lock:
        if src not in syn_counters:
            syn_counters[src] = IPAddressInfo(src)
            # start timer reset count after 10 sec
            threading.Timer(10, syn_counters[src].reset_count).start()
        syn_counters[src].increment_count()
        
        if syn_counters[src].count > LIMIT_S and not syn_counters[src].notification_sent:
            print("*************************************")
            print(f'ALERT: Possible SYN Flood attack detected from {src} ')
            print("*************************************")
            syn_counters[src].notification_sent = True
            
def handle_packet(packet, src_ip):
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
    ip_header_length = (ip_header[0] & 0x0F) * 4 
    tcp_header = packet[ip_header_length:ip_header_length+20] 
    tcp_header = struct.unpack('!HHLLBBHHH', tcp_header) 
    source_port, dest_port = tcp_header[0], tcp_header[1] 
    payload = packet[ip_header_length+20:] 
    if dest_port == 80 or dest_port == 443: 
   
        if payload.startswith(b'GET') or payload.startswith(b'POST'):
            print('HTTP request')
            update_http_requests(src_ip)

def update_http_requests(ip):
    with lock:
        if ip not in http_requests:
            http_requests[ip] = IPAddressInfo(ip)
            threading.Timer(10, http_requests[ip].reset_count).start()
        http_requests[ip].increment_count()
       
        if http_requests[ip].count > LIMIT and not http_requests[ip].notification_sent:
            print("****************************************")
            print(f'Alert: Possible HTTP DoS attack detected from {ip} ')
            print("*****************************************")
            http_requests[ip].notification_sent = True

def reset_counter(ip_addr):
    with lock:
        syn_counters[ip_addr] = 0

def main():
    print("Sniffer starting...")
    print("To stop press Ctrl+C.")

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
 
    gateways = netifaces.gateways()
    if netifaces.AF_INET in gateways['default']:
        default_interface = gateways['default'][netifaces.AF_INET][1]
        print(default_interface)
    else:
        default_interface = 'eth3'

    print(default_interface)
    conn.bind((default_interface, 0))

    
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print("Host IP:", local_ip)
    
    addr = netifaces.ifaddresses(default_interface)
    mac_address = addr[netifaces.AF_LINK][0]['addr']
    print("MAC address of the network interface:", mac_address)

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', raw_data[:14])
            dest_mac = get_mac_addr(dest_mac)
            src_mac = get_mac_addr(src_mac)
            data = raw_data[14:]
            print("MAC destination:", dest_mac, "Source MAC address:", src_mac, "Protocol:", eth_proto)
                      
            if eth_proto == 0x0800:  # IPv4
               
                process_ipv4(data)
            elif eth_proto == 0x0806:  # ARP
              
                process_arp(data)
            elif eth_proto == 0x86DD:  # IPv6
               
                process_ipv6(data)

    except KeyboardInterrupt:
        print("\nPacket capture statistics:")
        for packet_type, count in packet_counts.items():
            print(f"{packet_type}: {count}")

if __name__ == "__main__":
    main()
