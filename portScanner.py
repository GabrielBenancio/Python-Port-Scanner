import socket
import threading
from queue import Queue
from datetime import datetime

# Common ports/services
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    443: "HTTPS",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP TLS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Proxy"
}

# Thread lock for cleaner console output
print_lock = threading.Lock()

# Queue for ports
port_queue = Queue()

# Store open ports
open_ports = []

# Attempts to grab service banner
def banner_grab(sock):
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode().strip()
        return banner
    except:
        return "No Banner"

# Scans a single port
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)

        result = sock.connect_ex((target, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown Service")

            banner = "Unavailable"

            try:
                banner = banner_grab(sock)
            except:
                pass

            with print_lock:
                print(f"[+] Port {port} OPEN | Service: {service}")
                print(f"    Banner: {banner}\n")

            open_ports.append((port, service, banner))

        sock.close()

    except socket.gaierror:
        with print_lock:
            print("[!] Hostname could not be resolved")

    except socket.error:
        with print_lock:
            print("[!] Could not connect to server")

# Worker thread function
def worker(target):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port)
        port_queue.task_done()


# Saves scan results to a txt file
def save_results(target):
    filename = f"{target}_scan_results.txt"

    with open(filename, "w") as file:
        file.write(f"Port Scan Results for {target}\n")
        file.write("=" * 50 + "\n")

        if open_ports:
            for port, service, banner in open_ports:
                file.write(
                    f"Port: {port} | Service: {service} | Banner: {banner}\n"
                )
        else:
            file.write("No open ports found.\n")

    print(f"\n[*] Results saved to {filename}")


# Main Scan Function
def scan_target(target, max_ports):
    global open_ports
    open_ports = []

    print(f"\n{'=' * 60}")
    print(f"Starting Scan on {target}")
    print(f"Time Started: {datetime.now()}")
    print(f"{'=' * 60}\n")

    # Add ports to queue
    for port in range(1, max_ports + 1):
        port_queue.put(port)

    # Create threads
    thread_count = 100

    for _ in range(thread_count):
        thread = threading.Thread(target=worker, args=(target,))
        thread.daemon = True
        thread.start()

    # Wait for all tasks to finish
    port_queue.join()

    print(f"\n[*] Scan Completed for {target}")
    print(f"[*] Total Open Ports Found: {len(open_ports)}")

    save_results(target)



targets = input("[*] Enter target(s) (comma-separated): ")
max_ports = int(input("[*] Enter max port number to scan: "))

# Multiple targets
if ',' in targets:
    print("\n[*] Multiple Targets Detected")

    for target in targets.split(','):
        scan_target(target.strip(), max_ports)

# Single target
else:
    scan_target(targets.strip(), max_ports)