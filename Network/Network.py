###############################################################
#             Instituto Tecnologico de Costa Rica             #
#                  Maestria en Computacion                    #
#                                                             #
#   Estudiante                                                #
#   Kathy Brenes Guerrero                                     #
#                                                             #
#   Fecha                                                     # 
#   Marzo 2021                                                #
###############################################################

import sys
from scapy.all import *
import subprocess

def check_selinux_context(file_path):
    try:
        # Run the adb shell command to get SELinux context
        result = subprocess.run(['adb', 'shell', 'ls', '-Z', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            # SELinux context information is available
            print(f"SELinux context for {file_path}:\n{result.stdout}")
        else:
            # SELinux context retrieval failed
            print(f"Failed to retrieve SELinux context for {file_path}. Error: {result.stderr}")

    except Exception as e:
        print(f"An error occurred: {e}")

def check_open_ports(target_ip, ports):
    open_ports = []
    closed_ports = []

    for port in ports:
        # Craft a TCP SYN packet
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        # Send the packet and wait for a response
        response = sr1(packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                open_ports.append(port)
                send(IP(dst=target_ip) / TCP(dport=port, flags="R"))  # Send a reset packet
            elif response[TCP].flags == 0x14:  # RST-ACK
                closed_ports.append(port)

    return open_ports, closed_ports

def analyze_http_traffic(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            # Assuming HTTP traffic
            http_payload = packet[Raw].load.decode(errors='ignore')

            # Look for keywords that might indicate excessive privileges
            keywords = ["admin", "root", "grant_permission", "elevated_privileges"]
            if any(keyword in http_payload.lower() for keyword in keywords):
                print("Potential HTTP Request with Excessive Privileges:")
                print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")
                print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
                print("HTTP Payload:")
                print(http_payload)
                print("-" * 50)
                
def scan_network():
    if len(sys.argv) != 2:
        print("Usage: python script.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    common_ports = [21, 22, 23, 80, 443, 445, 3389]  # Add more ports as needed

    print(f"Checking for open ports on {target_ip}...")
    open_ports, closed_ports = check_open_ports(target_ip, common_ports)

    print("Open ports:", open_ports)
    print("Closed ports:", closed_ports)
