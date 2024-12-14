from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    """
    Callback function to process each captured packet.
    """
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "Unknown"
        
        # Determine protocol type
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"

        # Display packet information
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocol}")

        # Extract and display payload data (if any)
        payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload) if UDP in packet else b''
        if payload:
            print(f"Payload: {payload[:50]}...")  # Print first 50 bytes of payload
        print("-" * 50)

def main():
    """
    Main function to start packet sniffing.
    """
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    
    # Start sniffing packets
    try:
        sniff(prn=process_packet, filter="ip", store=False)
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
