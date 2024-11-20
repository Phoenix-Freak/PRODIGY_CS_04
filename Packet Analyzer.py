from scapy.all import *
import sys

# Function to display network interface details
def show_available_interfaces():
    interfaces = get_if_list()
    print("\nAvailable Network Interfaces:")
    for idx, iface in enumerate(interfaces):
        # Show interface index and name
        print(f"{idx}: {iface}")
    return interfaces

# Function to get protocol names based on protocol number
def get_protocol_name(proto):
    """
    Return the protocol name based on the protocol number.
    """
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto, f"unknown ({proto})")

# Packet callback function to process and display information for each captured packet
def packet_callback(packet):
    """
    Callback function to handle and display packet information
    """
    if packet.haslayer(IP): # Check if the packet has an IP layer
        ip_info = {
            "Source IP": packet[IP].src,
            "Destination IP": packet[IP].dst,
            "Protocol": get_protocol_name(packet[IP].proto),
            "TTL": packet[IP].ttl
        }
        # Display the packet information
        print("Packet Captured.")
        for key, value in ip_info.items():
            print(f" {key}: {value}")
        print("_" * 50)

# Function to start Packet Sniffing
def packet_sniffer():
    """
    Capture and Analyze Network Packets.
    """
    interfaces = show_available_interfaces() # Display available network intefaces

    # Prompt the user to select an interface
    selected_interface = input("\nEnter the network interface (e.g., 'MediaTek Wi-Fi' or '17'): ")

    # Handle the user input to select the correct interface
    try:
        # If input is numeric, convert it to an integer index
        if selected_interface.isdigit():
            interface_index = int(selected_interface)
            # Get the name of the interface from the index
            selected_interface = interfaces[interface_index]
        else:
            print("Invalid Input! Please enter a valid index number.")
            sys.exit(1)
    except (ValueError, IndexError):
        print("Invalid interface input. Exiting...")
        sys.exit(1)

    print(f"Sniffing packets on {selected_interface}...")

    # Set the interface for sniffing
    conf.iface = selected_interface

    try:
        # Start sniffing packets
        sniff(iface=selected_interface, prn=packet_callback)

    except KeyboardInterrupt:
        print("\nStopping Packet Sniffer...")

if __name__ == "__main__":
    packet_sniffer()