
"""
MOVILHAX v1.0 - Network Device Scanner
Discovers devices on your local network.
Shows IP, MAC, Subnet Mask, Hostname, and Vendor.
For authorized network administration use only.
"""

import sys
import os

if sys.platform != 'linux':
    sys.exit("\033[91m[!] Movilhax requires a Linux system.\033[0m")

if os.geteuid() != 0:
    sys.exit("\033[91m[!] Root privileges required.\n    Usage: sudo movilhax\033[0m")

import logging
logging.getLogger("scapy").setLevel(logging.ERROR)

try:
    from scapy.all import ARP, Ether, srp, conf
except ImportError:
    sys.exit("\033[91m[!] Scapy not installed. Run: sudo ./install.sh\033[0m")

import time
import socket
import subprocess
import re
import ipaddress
import random
import signal

G  = '\033[92m'         
DG = '\033[32m'         
R  = '\033[91m'         
Y  = '\033[93m'         
C  = '\033[96m'         
W  = '\033[97m'         
GY = '\033[90m'         
BD = '\033[1m'          
DM = '\033[2m'          
X  = '\033[0m'          
NG = '\033[38;5;46m'    

BANNER = f"""{NG}{BD}

    ███╗   ███╗  ██████╗  ██╗   ██╗ ██╗ ██╗
    ████╗ ████║ ██╔═══██╗ ██║   ██║ ██║ ██║
    ██╔████╔██║ ██║   ██║ ██║   ██║ ██║ ██║
    ██║╚██╔╝██║ ██║   ██║ ╚██╗ ██╔╝ ██║ ██║
    ██║ ╚═╝ ██║ ╚██████╔╝  ╚████╔╝  ██║ ███████╗
    ╚═╝     ╚═╝  ╚═════╝    ╚═══╝   ╚═╝ ╚══════╝
               ██╗  ██╗  █████╗  ██╗  ██╗
               ██║  ██║ ██╔══██╗ ╚██╗██╔╝
               ███████║ ███████║  ╚███╔╝
               ██╔══██║ ██╔══██║  ██╔██╗
               ██║  ██║ ██║  ██║ ██╔╝ ██╗
               ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝

    {C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NG}
              {W}Network Device Scanner v1.0{NG}
               {GY}For authorized use only{NG}
    {C}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{X}
"""

MAC_VENDORS = {
    # ── Apple ──
    "00:1C:B3": "Apple", "3C:15:C2": "Apple", "A4:83:E7": "Apple",
    "00:25:00": "Apple", "68:DB:CA": "Apple", "AC:87:A3": "Apple",
    "F0:D1:A9": "Apple", "14:99:E2": "Apple", "20:78:F0": "Apple",
    "6C:94:66": "Apple", "F4:5C:89": "Apple", "D0:E1:40": "Apple",
    "78:7B:8A": "Apple", "B8:17:C2": "Apple", "9C:FC:01": "Apple",
    "38:F9:D3": "Apple", "C8:69:CD": "Apple", "DC:A9:04": "Apple",
    "E0:5F:45": "Apple", "A8:66:7F": "Apple", "54:26:96": "Apple",
    "BC:52:B7": "Apple", "84:FC:FE": "Apple", "1C:36:BB": "Apple",
    # ── Samsung ──
    "00:21:19": "Samsung", "00:1C:43": "Samsung", "A8:F2:74": "Samsung",
    "00:26:37": "Samsung", "50:01:BB": "Samsung", "C4:73:1E": "Samsung",
    "34:C3:AC": "Samsung", "00:24:54": "Samsung", "00:25:66": "Samsung",
    "00:26:5D": "Samsung", "08:37:3D": "Samsung", "14:49:E0": "Samsung",
    "4C:BC:48": "Samsung", "78:52:1A": "Samsung", "88:32:9B": "Samsung",
    "CC:3A:61": "Samsung", "E4:7C:F9": "Samsung", "F0:25:B7": "Samsung",
    "94:35:0A": "Samsung", "A0:82:1F": "Samsung", "D0:87:E2": "Samsung",
    # ── Huawei ──
    "00:E0:FC": "Huawei", "00:25:9E": "Huawei", "00:46:4B": "Huawei",
    "00:1E:10": "Huawei", "00:22:A1": "Huawei", "00:18:82": "Huawei",
    "AC:E8:7B": "Huawei", "20:A6:80": "Huawei", "48:46:FB": "Huawei",
    "70:72:3C": "Huawei", "24:09:95": "Huawei", "D4:6E:5C": "Huawei",
    "10:44:00": "Huawei", "C8:D1:5E": "Huawei", "28:31:52": "Huawei",
    # ── Xiaomi ──
    "64:B4:73": "Xiaomi", "28:6C:07": "Xiaomi", "0C:1D:AF": "Xiaomi",
    "8C:BE:BE": "Xiaomi", "F8:A4:5F": "Xiaomi", "74:23:44": "Xiaomi",
    "FC:64:BA": "Xiaomi", "18:59:36": "Xiaomi", "7C:1D:D9": "Xiaomi",
    "34:CE:00": "Xiaomi", "50:64:2B": "Xiaomi", "58:44:98": "Xiaomi",
    "9C:99:A0": "Xiaomi", "64:CC:2E": "Xiaomi", "28:E3:1F": "Xiaomi",
    # ── Google / Pixel ──
    "3C:5A:B4": "Google", "F4:F5:D8": "Google", "94:EB:2C": "Google",
    "54:60:09": "Google", "A4:77:33": "Google", "30:FD:38": "Google",
    # ── OnePlus ──
    "C0:EE:FB": "OnePlus", "94:65:2D": "OnePlus",
    # ── Sony / Xperia ──
    "FC:F1:52": "Sony", "00:13:A9": "Sony", "AC:9B:0A": "Sony",
    "00:24:BE": "Sony", "B4:52:7D": "Sony", "00:19:C5": "Sony",
    # ── Motorola ──
    "00:0C:E5": "Motorola", "00:0A:28": "Motorola", "00:19:2C": "Motorola",
    "68:C4:4D": "Motorola", "40:98:AD": "Motorola", "E4:90:7E": "Motorola",
    # ── LG ──
    "00:1C:62": "LG", "00:1E:75": "LG", "00:22:A9": "LG",
    "00:24:83": "LG", "10:68:3F": "LG", "30:76:6F": "LG",
    "58:A2:B5": "LG", "CC:FA:00": "LG", "48:59:29": "LG",
    # ── OPPO / Realme ──
    "A4:3D:78": "OPPO", "CC:A2:23": "OPPO", "2C:5B:E1": "OPPO",
    "E8:61:7E": "OPPO", "18:C5:8A": "Realme",
    # ── Vivo ──
    "BC:1A:E4": "Vivo", "44:C3:46": "Vivo", "D0:E3:2C": "Vivo",
    # ── Nokia / HMD ──
    "00:15:A0": "Nokia", "00:1A:DC": "Nokia", "00:1D:FD": "Nokia",
    "00:1F:5C": "Nokia", "00:21:08": "Nokia",
    # ── Amazon (Kindle/Fire) ──
    "F0:F0:A4": "Amazon", "68:54:FD": "Amazon",
    "44:65:0D": "Amazon", "A0:02:DC": "Amazon",
    # ── Routers / Network Equipment ──
    "00:1A:2B": "Cisco", "00:1B:2B": "Cisco", "00:1D:46": "Cisco",
    "00:23:CD": "TP-Link", "50:C7:BF": "TP-Link", "B0:4E:26": "TP-Link",
    "14:CC:20": "TP-Link", "E8:94:F6": "TP-Link", "60:32:B1": "TP-Link",
    "E4:F4:C6": "Netgear", "C4:3D:C7": "Netgear", "B0:7F:B9": "Netgear",
    "00:24:01": "D-Link", "1C:AF:F7": "D-Link", "FC:75:16": "D-Link",
    "F8:75:A4": "ASUS", "04:D9:F5": "ASUS", "1C:87:2C": "ASUS",
    "00:0F:66": "Cisco-Linksys", "00:22:6B": "Cisco-Linksys",
    "C0:56:27": "Belkin", "94:10:3E": "Belkin",
    # ── Intel (Laptops/PCs) ──
    "00:1B:21": "Intel", "00:1E:64": "Intel", "00:1F:3B": "Intel",
    "00:22:FA": "Intel", "3C:97:0E": "Intel", "5C:51:4F": "Intel",
    "8C:70:5A": "Intel", "A4:34:D9": "Intel", "48:51:B7": "Intel",
    # ── Others ──
    "00:50:56": "VMware", "00:0C:29": "VMware", "08:00:27": "VirtualBox",
    "00:15:5D": "Hyper-V", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1A:A0": "Dell", "00:25:B3": "HP",
}

MOBILE_BRANDS = {
    "Apple", "Samsung", "Huawei", "Xiaomi", "Google", "OnePlus",
    "Sony", "Motorola", "LG", "OPPO", "Nokia", "Vivo", "Realme",
    "Amazon",
}


def typing(text, delay=0.02, color=G):
    """Print text with typing effect."""
    for char in text:
        sys.stdout.write(f"{color}{char}{X}")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def loading_bar(text, duration=2.0, width=40):
    """Display animated loading bar."""
    for i in range(width + 1):
        pct = int(i / width * 100)
        filled = f"{G}{'█' * i}"
        empty = f"{GY}{'░' * (width - i)}"
        sys.stdout.write(f"\r  {G}{text} [{filled}{empty}{G}] {W}{pct}%{X}")
        sys.stdout.flush()
        time.sleep(duration / width)
    print()


def spinner(text, duration=2.0):
    """Display spinning animation."""
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(f"\r  {G}{frames[i % len(frames)]} {text}{X}  ")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\r  {G}[+] {text}{X}  \n")


def matrix_rain(duration=1.0):
    """Brief matrix rain effect for startup."""
    chars = "01アイウエオカキクケコサシスセソタチツテト"
    width = 55
    end_time = time.time() + duration
    while time.time() < end_time:
        line = ''.join(random.choice(chars) for _ in range(width))
        shade = random.choice([DG, DM + DG])
        print(f"    {shade}{line}{X}")
        time.sleep(0.06)


def run_cmd(cmd, timeout=5):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_default_interface():
    """Get the default network interface."""
    output = run_cmd(['ip', 'route', 'show', 'default'])
    match = re.search(r'dev\s+(\S+)', output)
    if match:
        return match.group(1)

    # Fallback: first non-loopback interface
    for name in ['eth0', 'wlan0', 'enp0s3', 'ens33', 'wlp2s0', 'wlp3s0']:
        if os.path.exists(f'/sys/class/net/{name}'):
            return name

    try:
        ifaces = os.listdir('/sys/class/net/')
        for iface in ifaces:
            if iface != 'lo':
                return iface
    except OSError:
        pass
    return None


def get_interface_ip(iface):
    """Get IPv4 address of an interface."""
    output = run_cmd(['ip', '-4', 'addr', 'show', iface])
    match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', output)
    return match.group(1) if match else None


def get_interface_mac(iface):
    """Get MAC address of an interface."""
    try:
        with open(f'/sys/class/net/{iface}/address') as f:
            return f.read().strip().upper()
    except OSError:
        return "N/A"


def get_subnet_mask(iface):
    """Get subnet mask as dotted notation and CIDR prefix length."""
    output = run_cmd(['ip', '-4', 'addr', 'show', iface])
    match = re.search(r'inet\s+\d+\.\d+\.\d+\.\d+/(\d+)', output)
    if match:
        prefix = int(match.group(1))
        mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        mask_str = (
            f"{(mask_int >> 24) & 0xFF}."
            f"{(mask_int >> 16) & 0xFF}."
            f"{(mask_int >> 8) & 0xFF}."
            f"{mask_int & 0xFF}"
        )
        return mask_str, prefix
    return "255.255.255.0", 24


def get_gateway():
    """Get default gateway IP."""
    output = run_cmd(['ip', 'route', 'show', 'default'])
    match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', output)
    return match.group(1) if match else None


def get_network_cidr(ip, prefix):
    """Calculate network CIDR from IP and prefix."""
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(network)
    except ValueError:
        return f"{ip}/{prefix}"


def get_hostname(ip):
    """Resolve hostname from IP. Tries DNS, then avahi/mDNS."""
    # Standard reverse DNS
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    # mDNS via avahi (if installed)
    output = run_cmd(['avahi-resolve-address', ip], timeout=3)
    if output:
        parts = output.split()
        if len(parts) >= 2:
            return parts[1]

    return "N/A"


def get_vendor(mac):
    """Look up vendor from MAC OUI prefix."""
    prefix = mac[:8].upper()

    # Built-in database
    vendor = MAC_VENDORS.get(prefix)
    if vendor:
        return vendor

    # Try system OUI files (nmap, arp-scan)
    compact = prefix.replace(':', '')
    for db_path in ['/usr/share/nmap/nmap-mac-prefixes',
                    '/usr/share/arp-scan/ieee-oui.txt',
                    '/usr/share/ieee-data/oui.txt']:
        if os.path.exists(db_path):
            output = run_cmd(['grep', '-i', '-m', '1', compact, db_path])
            if output:
                parts = output.split('\t')
                if len(parts) >= 2:
                    return parts[-1].strip()[:20]
                parts = output.split(maxsplit=1)
                if len(parts) >= 2:
                    return parts[-1].strip()[:20]

    return "Unknown"


def arp_scan(target_cidr, iface=None, timeout=3):
    """Perform ARP scan on target network. Returns list of device dicts."""
    conf.verb = 0

    arp = ARP(pdst=target_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result, _ = srp(packet, timeout=timeout, iface=iface, verbose=False)
    except PermissionError:
        print(f"\n  {R}[!] Permission denied. Run as root.{X}")
        return []
    except Exception as e:
        print(f"\n  {R}[!] Scan error: {e}{X}")
        return []

    devices = []
    for sent, received in result:
        mac = received.hwsrc.upper()
        ip = received.psrc
        vendor = get_vendor(mac)
        hostname = get_hostname(ip)
        is_mobile = vendor in MOBILE_BRANDS

        devices.append({
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'hostname': hostname,
            'is_mobile': is_mobile,
        })

    devices.sort(key=lambda d: tuple(int(p) for p in d['ip'].split('.')))
    return devices


def show_network_info(iface, ip, mask, prefix, gateway, local_mac):
    """Display local network information panel."""
    cidr = get_network_cidr(ip, prefix)
    gw = gateway or "N/A"

    print(f"""
  {C}╔══════════════════════════════════════════════════════╗
  ║{BD}{W}            NETWORK INFORMATION                     {X}{C}║
  ╠══════════════════════════════════════════════════════╣
  ║  {G}Interface   :{X} {W}{iface:<38}{C}║
  ║  {G}Local IP    :{X} {W}{ip:<38}{C}║
  ║  {G}MAC Address :{X} {W}{local_mac:<38}{C}║
  ║  {G}Subnet Mask :{X} {W}{mask:<38}{C}║
  ║  {G}Gateway     :{X} {W}{gw:<38}{C}║
  ║  {G}Network     :{X} {W}{cidr:<38}{C}║
  ╚══════════════════════════════════════════════════════╝{X}
""")


def show_results(devices, mask):
    """Display all scan results in a table."""
    if not devices:
        print(f"\n  {Y}[!] No devices found on the network.{X}\n")
        return

    mobile_count = sum(1 for d in devices if d['is_mobile'])
    print(f"\n  {G}{BD}[+] {len(devices)} device(s) found "
          f"| {Y}{mobile_count} potential mobile(s){X}\n")

    # Separator line
    sep = f"  {C}{'─' * 90}{X}"

    # Header
    print(sep)
    print(f"  {C}{BD}{'#':>3}  {'IP Address':<17}{'MAC Address':<20}"
          f"{'Mask':<17}{'Hostname':<20}{'Vendor':<15}{X}")
    print(sep)

    for i, dev in enumerate(devices, 1):
        color = Y if dev['is_mobile'] else W
        tag = f" {Y}[MOB]{X}" if dev['is_mobile'] else ""
        hostname = dev['hostname'][:19]
        vendor = dev['vendor'][:14]

        print(f"  {color}{i:>3}  {dev['ip']:<17}{dev['mac']:<20}"
              f"{mask:<17}{hostname:<20}{vendor:<14}{X}{tag}")

    print(sep)
    print()


def show_device_detail(dev, mask):
    """Display detailed information for a single device."""
    mob_flag = f"{Y}YES{X}" if dev['is_mobile'] else f"{W}No{X}"

    print(f"""
  {G}╔══════════════════════════════════════════════════════╗
  ║{BD}{W}              DEVICE DETAILS                        {X}{G}║
  ╠══════════════════════════════════════════════════════╣
  ║  {C}IP Address   :{X} {W}{dev['ip']:<37}{G}║
  ║  {C}MAC Address  :{X} {W}{dev['mac']:<37}{G}║
  ║  {C}Subnet Mask  :{X} {W}{mask:<37}{G}║
  ║  {C}Device Name  :{X} {W}{dev['hostname'][:37]:<37}{G}║
  ║  {C}Vendor       :{X} {W}{dev['vendor']:<37}{G}║
  ║  {C}Mobile?      :{X} {mob_flag:<46}{G}║
  ╚══════════════════════════════════════════════════════╝{X}
""")


def boot_sequence():
    """Animated hacking-style startup."""
    os.system('clear')
    matrix_rain(duration=1.2)
    os.system('clear')
    print(BANNER)
    time.sleep(0.3)

    steps = [
        ("Initializing Movilhax engine", 0.015),
        ("Loading network modules", 0.012),
        ("Building MAC vendor database", 0.010),
        ("Configuring ARP packet engine", 0.012),
        ("System ready", 0.018),
    ]

    for text, delay in steps:
        typing(f"  [*] {text}...", delay=delay, color=DG)
        time.sleep(0.15)

    print()
    loading_bar("Initializing", duration=1.5)
    print()


def menu(iface, ip, mask, prefix, gateway, local_mac):
    """Main interactive menu loop."""
    cidr = get_network_cidr(ip, prefix)
    devices = []

    while True:
        print(f"""
  {G}{BD}
  ╔════════════════════════════════=======═╗
  ║          MOVILHAX  -  MENU             ║
  ╠════════════════════════════════════════╣
  ║                                        ║
  ║  {C}[1]{G}  Scan full network          ║
  ║  {C}[2]{G}  Scan specific IP           ║
  ║  {C}[3]{G}  Show network info          ║
  ║  {C}[4]{G}  Show last scan results     ║
  ║  {C}[5]{G}  Monitor device (ping)      ║
  ║  {C}[0]{G}  Exit                       ║
  ║                                        ║
  ╚════════════════════════════════════════╝{X}
""")

        try:
            choice = input(f"  {G}movilhax{GY}@{G}{iface}{W} > {X}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {G}[*] Exiting Movilhax. Goodbye.{X}\n")
            sys.exit(0)

        # ── Option 1: Full network scan ──
        if choice == '1':
            print()
            spinner("Preparing ARP scanner", duration=1.0)
            print(f"  {G}[*] Scanning {C}{cidr}{G} on {C}{iface}{G}...{X}")
            print(f"  {GY}    This may take a few seconds...{X}\n")
            loading_bar("Scanning network", duration=2.0)

            devices = arp_scan(cidr, iface=iface)
            show_results(devices, mask)

        # ── Option 2: Scan specific IP ──
        elif choice == '2':
            try:
                target = input(f"\n  {C}[?] Enter target IP address: {X}").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n  {Y}[!] Cancelled.{X}")
                continue

            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                print(f"  {R}[!] Invalid IP address format.{X}")
                continue

            print()
            spinner(f"Scanning {target}", duration=1.5)

            result = arp_scan(target, iface=iface, timeout=5)
            if result:
                show_device_detail(result[0], mask)
            else:
                print(f"  {Y}[!] Device not found via ARP.{X}")
                print(f"  {GY}[*] Trying ICMP ping...{X}")
                ping_out = run_cmd(['ping', '-c', '3', '-W', '2', target], timeout=10)
                if 'bytes from' in ping_out.lower() or 'ttl=' in ping_out.lower():
                    print(f"  {G}[+] Host is UP (ICMP) but did not respond to ARP.{X}")
                    print(f"  {GY}    May be on a different subnet or has ARP filtering.{X}")
                else:
                    print(f"  {R}[!] Host appears to be DOWN.{X}")

      
        elif choice == '3':
            show_network_info(iface, ip, mask, prefix, gateway, local_mac)

        
        elif choice == '4':
            if not devices:
                print(f"\n  {Y}[!] No scan results yet. Run a scan first (option 1).{X}")
                continue

            show_results(devices, mask)

        
            try:
                sel = input(
                    f"  {C}[?] Enter device # for details "
                    f"(or Enter to skip): {X}"
                ).strip()
            except (KeyboardInterrupt, EOFError):
                continue

            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(devices):
                    show_device_detail(devices[idx], mask)
                else:
                    print(f"  {R}[!] Invalid device number.{X}")

        # ── Option 5: Monitor device ──
        elif choice == '5':
            if not devices:
                print(f"\n  {Y}[!] Run a network scan first (option 1).{X}")
                continue

            print(f"\n  {C}[?] Select device # to monitor (1-{len(devices)}):{X}")
            try:
                sel = input(f"  {G}> {X}").strip()
                idx = int(sel) - 1
                if not (0 <= idx < len(devices)):
                    print(f"  {R}[!] Invalid selection.{X}")
                    continue
            except (ValueError, KeyboardInterrupt, EOFError):
                print(f"\n  {Y}[!] Cancelled.{X}")
                continue

            target_dev = devices[idx]
            print(f"\n  {G}[*] Monitoring {C}{target_dev['ip']}{G} "
                  f"({target_dev['vendor']})...{X}")
            print(f"  {GY}    Press Ctrl+C to stop.{X}\n")

            try:
                while True:
                    ping_out = run_cmd(
                        ['ping', '-c', '1', '-W', '1', target_dev['ip']],
                        timeout=5
                    )
                    ts = time.strftime('%H:%M:%S')
                    if 'bytes from' in ping_out.lower() or 'ttl=' in ping_out.lower():
                        lat_match = re.search(r'time[=<]([\d.]+)', ping_out)
                        lat = lat_match.group(1) if lat_match else "?"
                        print(f"  {G}[{ts}] {target_dev['ip']} "
                              f"-- ONLINE -- {lat}ms{X}")
                    else:
                        print(f"  {R}[{ts}] {target_dev['ip']} "
                              f"-- OFFLINE{X}")
                    time.sleep(2)
            except KeyboardInterrupt:
                print(f"\n\n  {Y}[!] Monitoring stopped.{X}")

        
        elif choice == '0':
            print(f"\n  {G}[*] Shutting down Movilhax...{X}")
            typing("  [*] Cleaning up...", delay=0.02, color=DG)
            time.sleep(0.3)
            print(f"  {G}[+] Goodbye.{X}\n")
            sys.exit(0)

        else:
            print(f"  {R}[!] Invalid option.{X}")


def main():
    signal.signal(signal.SIGINT,
                  lambda s, f: (print(f"\n\n  {G}[*] Interrupted. Goodbye.{X}\n"),
                                sys.exit(0)))

    boot_sequence()

    # Detect network configuration
    typing("  [*] Detecting network interface...", delay=0.02, color=DG)
    iface = get_default_interface()

    if not iface:
        print(f"  {R}[!] No network interface found. Check your connection.{X}")
        sys.exit(1)

    ip = get_interface_ip(iface)
    if not ip or ip == '0.0.0.0':
        print(f"  {R}[!] No IP address on {iface}. Check your connection.{X}")
        sys.exit(1)

    local_mac = get_interface_mac(iface)
    mask, prefix = get_subnet_mask(iface)
    gateway = get_gateway()
    cidr = get_network_cidr(ip, prefix)

    print(f"  {G}[+] Interface : {W}{iface}{X}")
    print(f"  {G}[+] Local IP  : {W}{ip}{X}")
    print(f"  {G}[+] MAC       : {W}{local_mac}{X}")
    print(f"  {G}[+] Gateway   : {W}{gateway or 'N/A'}{X}")
    print(f"  {G}[+] Network   : {W}{cidr}{X}")
    print()
    time.sleep(0.5)
    typing("  [+] Movilhax is ready.", delay=0.025, color=G)

    show_network_info(iface, ip, mask, prefix, gateway, local_mac)
    menu(iface, ip, mask, prefix, gateway, local_mac)


if __name__ == '__main__':
    main()
