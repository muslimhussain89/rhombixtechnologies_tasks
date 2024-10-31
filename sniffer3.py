from scapy.all import sniff, IP, TCP, UDP, ICMP

# Initialize total counters for each protocol type
http_total = 0
tcp_total = 0
udp_total = 0
icmp_total = 0

# Initialize transmitted and received counters for each protocol type
http_transmitted = 0
http_received = 0
tcp_transmitted = 0
tcp_received = 0
udp_transmitted = 0
udp_received = 0
icmp_transmitted = 0
icmp_received = 0

def packet_callback(packet):
    global http_total, tcp_total, udp_total, icmp_total
    global http_transmitted, http_received
    global tcp_transmitted, tcp_received
    global udp_transmitted, udp_received
    global icmp_transmitted, icmp_received
    
    if packet.haslayer(IP):
        print(f"Protocol: {packet[IP].proto}")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")

        # Determine if the packet is transmitted or received
        if packet[IP].src == "10.0.2.15":
            direction = "transmitted"
        else:
            direction = "received"

        # Check for TCP packets
        if packet.haslayer(TCP):
            tcp_total += 1
            if direction == "transmitted":
                tcp_transmitted += 1
            else:
                tcp_received += 1
                
            print("--- TCP Packet ---")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            print(f"Flags: {packet[TCP].flags}")

            # Check for HTTP traffic on port 80
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                http_total += 1
                if direction == "transmitted":
                    http_transmitted += 1
                else:
                    http_received += 1

                print("--- HTTP Data ---")
                http_payload = bytes(packet[TCP].payload)
                if http_payload:
                    try:
                        http_text = http_payload.decode('utf-8')
                        print(http_text)
                    except UnicodeDecodeError:
                        print("HTTP Data: Non-UTF-8 content")
        
        elif packet.haslayer(UDP):
            udp_total += 1
            if direction == "transmitted":
                udp_transmitted += 1
            else:
                udp_received += 1

            print("--- UDP Packet ---")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            icmp_total += 1
            if direction == "transmitted":
                icmp_transmitted += 1
            else:
                icmp_received += 1

            print("--- ICMP Packet ---")
            print(f"Type: {packet[ICMP].type}")
            print(f"Code: {packet[ICMP].code}")

        # Print the count of packets so far, including total, transmitted, and received
        print(f"\nCounts so far:")
        print(f"HTTP: Total: {http_total}, Transmitted: {http_transmitted}, Received: {http_received}")
        print(f"TCP: Total: {tcp_total}, Transmitted: {tcp_transmitted}, Received: {tcp_received}")
        print(f"UDP: Total: {udp_total}, Transmitted: {udp_transmitted}, Received: {udp_received}")
        print(f"ICMP: Total: {icmp_total}, Transmitted: {icmp_transmitted}, Received: {icmp_received}\n")

sniff(prn=packet_callback, store=False)
