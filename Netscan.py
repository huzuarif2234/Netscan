import socket
import logging
import warnings
import concurrent.futures
from scapy.all import IP, ICMP, ARP, Ether, sr1, srp

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.simplefilter("ignore")


# ------------------ Get MAC Address Function ------------------
def get_mac(ip):
    """
    Get the MAC address of a target IP using an ARP request.
    This prevents Scapy from defaulting to broadcast.
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request
    response, _ = srp(arp_packet, timeout=2, verbose=False)

    if response:
        return response[0][1].hwsrc  # Return the MAC address
    return None


# ------------------ Host Discovery (ICMP Ping Sweep) ------------------
def ping_sweep(network):
    """
    Scan the network for active hosts using ICMP Ping requests.
    """
    print(f"\n[+] Scanning network: {network}.0/24")
    live_hosts = []

    for ip in range(1, 255):  # Scan range 1-254
        ip_addr = f"{network}.{ip}"
        
        # Resolve MAC Address before sending packets
        mac = get_mac(ip_addr)
        if mac is None:
            continue  # Skip unreachable hosts
        
        packet = IP(dst=ip_addr)/ICMP()
        reply = sr1(packet, timeout=0.5, verbose=False)

        if reply:
            print(f"[+] Host {ip_addr} is UP (MAC: {mac})")
            live_hosts.append(ip_addr)

    return live_hosts


# ------------------ Port Scanning ------------------
def scan_port(ip, port):
    """
    Scan a single port on a target IP to check if it's open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))

        if result == 0:
            print(f"[+] Port {port} is OPEN on {ip}")
            banner_grabbing(ip, port)  # Try to grab service banner
        sock.close()

    except Exception as e:
        print(f"[-] Error scanning {ip}:{port} - {e}")


# ------------------ Multi-threaded Port Scanner ------------------
def multi_threaded_scan(target_ip, ports):
    """
    Uses threading to scan multiple ports efficiently.
    """
    print(f"\n[+] Scanning ports on {target_ip}...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(scan_port, [target_ip]*len(ports), ports)


# ------------------ Service Detection (Banner Grabbing) ------------------
def banner_grabbing(ip, port):
    """
    Attempts to grab the banner of an open port to identify the running service.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        print(f"    [Service Detected] {ip}:{port} -> {banner}")
        sock.close()
    except:
        pass  # Some services do not return banners


# ------------------ Main Function ------------------
if __name__ == "__main__":
    print("=== Simple Python Network Scanner ===")

    # Get user input for network scan
    while True:
        target_network = input("\nEnter the network to scan (e.g., 192.168.1): ").strip()
        if target_network.count(".") == 2 and all(0 <= int(octet) <= 255 for octet in target_network.split(".")):
            break
        else:
            print("[-] Invalid input! Please enter only the first three octets (e.g., 192.168.1).")

    # Perform Host Discovery
    active_hosts = ping_sweep(target_network)

    if not active_hosts:
        print("[-] No active hosts found.")
    else:
        # Get user input for port scanning
        target_ports = input("\nEnter ports to scan (e.g., 22,80,443 or 1-1000): ").strip()

        # Parse port input
        if "-" in target_ports:
            start_port, end_port = map(int, target_ports.split("-"))
            ports = list(range(start_port, end_port + 1))
        else:
            ports = list(map(int, target_ports.split(",")))

        # Scan all active hosts
        for host in active_hosts:
            multi_threaded_scan(host, ports)
