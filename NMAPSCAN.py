import nmap
import threading
import time
import sys
import json
import os
from queue import Queue

# --- Termios/Tty Imports & getch() for Linux/macOS ---
# Conditional import for Windows compatibility
if sys.platform != "win32":
    import termios
    import tty

    def getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch
else:
    # For Windows, a simple input for Ctrl+T/Q is less practical in raw mode.
    # We'll just disable the interactive listener for Windows.
    def getch():
        # Placeholder for Windows; will not be used in listener thread
        # if listener is conditionally started.
        time.sleep(0.1) # Prevent busy-waiting
        return ''

# Globals
scanned_ports = 0
# For initial scan, total_ports is a bit abstract, as it's not a fixed number of ports,
# but rather a 'top-ports' or 'all-ports' scan. We'll adjust its meaning.
# For a full initial scan, we often don't know the exact number of ports scanned upfront.
# Let's adjust total_ports to represent something like "progress phases".
total_phases = 3 # e.g., Host Discovery, Top Ports Scan, OS/Service Detection
current_phase_idx = 0

start_time = None
running = True
lock = threading.Lock()
results = [] # To store the final Nmap scan data
scan_queue = Queue() # For scan tasks

# Define a more comprehensive set of initial Nmap arguments
# -sS: SYN scan (fastest)
# -sV: Service version detection
# -O: OS detection
# -sC: Default scripts (equivalent to --script=default)
# -Pn: Treat all hosts as online -- skip host discovery. Useful if firewall drops pings.
# -T4: Aggressive timing (faster)
# --top-ports 1000: Scans the 1000 most common ports. Good balance for initial scan.
# --traceroute: To gather hop information.
# --open: Only show open ports. (Might be too restrictive for initial discovery)
# --reason: Show reason for port state.
# --host-timeout 5m: Timeout for each host.
# --version-intensity 9: Higher intensity for version detection.
INITIAL_NMAP_ARGS = "-sS -sV -O -sC -T4 --top-ports 1000 --traceroute --reason --version-intensity 9"

# Optional: You could make this configurable or more dynamic based on user input
# For example: initial_nmap_args = input("Enter initial Nmap arguments (default: ...): ")

def update_progress(phase_name):
    global current_phase_idx, total_phases
    with lock:
        current_phase_idx += 1
        print(f"\n[PROGRESS] Phase {current_phase_idx}/{total_phases}: {phase_name}...")

def ctrl_listener():
    """Listens for Ctrl+T (status) and Ctrl+Q (quit) signals."""
    global running, scanned_ports, start_time, total_phases, current_phase_idx
    if sys.platform == "win32":
        print("Ctrl+T/Q listener is not supported on Windows in this terminal setup.")
        return

    print("Listener started. Press Ctrl+T for status, Ctrl+Q to quit.")
    while running:
        try:
            ch = getch()
            if ch == '\x14':  # Ctrl+T (ASCII 20)
                elapsed = time.time() - start_time
                with lock:
                    current_phase = current_phase_idx
                
                print(f"\n[Ctrl+T] Elapsed: {elapsed:.1f}s | Current Phase: {current_phase}/{total_phases}")
                # More detailed progress can be tricky without Nmap's direct progress callback,
                # but we can infer it from the phases.
                if current_phase < total_phases:
                    remaining_phases = total_phases - current_phase
                    # Estimate remaining time based on average phase duration so far (very rough)
                    avg_time_per_phase = elapsed / current_phase if current_phase > 0 else 0
                    est_remaining = remaining_phases * avg_time_per_phase
                    print(f"           Estimated Remaining Time (rough): {est_remaining:.1f}s\n")
                else:
                    print("           All initial scan phases completed.\n")

            elif ch == '\x11':  # Ctrl+Q (ASCII 17)
                print("\n[Ctrl+Q] Exit signal received. Stopping scan...\n")
                running = False
                break
        except Exception as e:
            # Handle potential errors if terminal state is messed up
            print(f"Error in Ctrl listener: {e}. Listener exiting.")
            running = False
            break
        time.sleep(0.05) # Small sleep to reduce CPU usage

def extract_scan_data(nm_scanner, target_ip):
    """
    Extracts relevant data from the python-nmap PortScanner object
    into a structured dictionary, mirroring Nmap's JSON output format.
    """
    extracted_data = []
    
    # nm_scanner.all_hosts() returns a list of IP addresses
    for host_ip in nm_scanner.all_hosts():
        host_info = nm_scanner[host_ip]

        host_entry = {
            "host": host_ip,
            "hostname": host_info.hostname() or "N/A",
            "state": host_info.state(), # e.g., 'up', 'down'
            "scaninfo": nm_scanner.scaninfo(), # Global scan info
            "protocols": {},
            "os": [],
            "hostscript": [],
            "traceroute": [],
            "uptime": None, # Placeholder for uptime if available
            "mac_address": None, # Placeholder for MAC if available
            "vendor": None, # Placeholder for vendor if available
            "addresses": host_info.get('addresses', {}), # raw addresses
            "ports_statistics": {
                "open_tcp_ports": [],
                "closed_tcp_ports": [],
                "filtered_tcp_ports": [],
                "open_udp_ports": [],
                "closed_udp_ports": [],
                "filtered_udp_ports": [],
            }
        }

        # --- Extract Port Information ---
        for proto in host_info.all_protocols():
            ports = []
            for port in sorted(host_info[proto].keys()):
                pdata = host_info[proto][port]
                port_detail = {
                    "port": port,
                    "state": pdata['state'],
                    "reason": pdata.get('reason', 'N/A'),
                    "service": pdata['name'],
                    "version": pdata.get('version', 'N/A'),
                    "product": pdata.get('product', 'N/A'),
                    "extrainfo": pdata.get('extrainfo', 'N/A'),
                    "cpe": pdata.get('cpe', 'N/A'),
                    "scripts": [] # For individual port scripts
                }

                # Populate port statistics
                if proto == 'tcp':
                    if pdata['state'] == 'open':
                        host_entry['ports_statistics']['open_tcp_ports'].append(port)
                    elif pdata['state'] == 'closed':
                        host_entry['ports_statistics']['closed_tcp_ports'].append(port)
                    elif pdata['state'] == 'filtered':
                        host_entry['ports_statistics']['filtered_tcp_ports'].append(port)
                elif proto == 'udp':
                    if pdata['state'] == 'open':
                        host_entry['ports_statistics']['open_udp_ports'].append(port)
                    elif pdata['state'] == 'closed':
                        host_entry['ports_statistics']['closed_udp_ports'].append(port)
                    elif pdata['state'] == 'filtered':
                        host_entry['ports_statistics']['filtered_udp_ports'].append(port)

                # Add script output for this port if available (e.g., from -sC)
                if 'script' in pdata:
                    for script_id, script_output in pdata['script'].items():
                        port_detail['scripts'].append({
                            "id": script_id,
                            "output": script_output
                        })
                ports.append(port_detail)
            host_entry["protocols"][proto] = ports

        # --- Extract OS Match Information ---
        if 'osmatch' in host_info:
            for osmatch in host_info['osmatch']:
                match_data = {
                    "name": osmatch['name'],
                    "accuracy": osmatch['accuracy'],
                    "osclass": []
                }
                for osclass in osmatch.get('osclass', []):
                    match_data['osclass'].append({
                        "type": osclass.get('type', 'N/A'),
                        "vendor": osclass.get('vendor', 'N/A'),
                        "osfamily": osclass.get('osfamily', 'N/A'),
                        "osgen": osclass.get('osgen', 'N/A'),
                        "cpe": osclass.get('cpe', [])
                    })
                host_entry["os"].append(match_data)

        # --- Extract Host Script Results ---
        if 'hostscript' in host_info:
            for script in host_info['hostscript']:
                host_entry["hostscript"].append({
                    "id": script['id'],
                    "output": script['output']
                })
        
        # --- Extract Traceroute Information ---
        if 'traceroute' in host_info:
            # The structure might vary. Assuming it's a list of dictionaries with 'hop', 'address', 'rtt'
            for hop in host_info['traceroute']:
                host_entry["traceroute"].append({
                    "hop": hop.get('hop'),
                    "address": hop.get('address'),
                    "rtt": hop.get('rtt')
                })

        # --- Extract Uptime, MAC, Vendor (if available) ---
        # These are usually top-level host properties, sometimes nested
        if 'uptime' in host_info:
            host_entry['uptime'] = host_info['uptime'].get('seconds') # Or 'lastboot'
        if 'mac' in host_info['addresses']:
            host_entry['mac_address'] = host_info['addresses']['mac']
            host_entry['vendor'] = host_info.get('vendor', 'N/A')

        extracted_data.append(host_entry)
    return extracted_data


def worker_scan(target, args, scan_id="initial_scan"):
    """Performs the Nmap scan for a given target with specified arguments."""
    global running, results
    nm = nmap.PortScanner()

    print(f"\n[{scan_id}] Starting Nmap scan on {target} with args: {args}")
    try:
        # Step 1: Host Discovery (if not using -Pn initially or for broader scope)
        # For --top-ports 1000, -Pn is often used, so this phase might be less explicit.
        # But for full network scans, this is critical.
        # update_progress("Host Discovery (Ping Scan)")
        # nm.scan(hosts=target, arguments='-sn -PR -T4') # Ping scan only
        # live_hosts = nm.all_hosts()
        # if not live_hosts:
        #     print(f"[{scan_id}] No live hosts found for {target}. Exiting scan worker.")
        #     return

        # Step 2: Main Scan
        update_progress("Scanning Top 1000 TCP Ports, OS & Service Detection")
        nm.scan(hosts=target, arguments=args)
        
        # Step 3: Data Extraction
        update_progress("Extracting and Processing Scan Data")
        if nm.all_hosts():
            parsed_data = extract_scan_data(nm, target)
            with lock:
                results.extend(parsed_data)
        else:
            print(f"[{scan_id}] No hosts found or no open ports for {target}. No data to extract.")

    except nmap.PortScannerError as e:
        print(f"[{scan_id}] Nmap Scan Error: {e}")
        # Optionally, log the error to a file
    except Exception as e:
        print(f"[{scan_id}] An unexpected error occurred during scan: {e}")
    finally:
        # Ensure progress is marked complete even if scan fails, to move on
        update_progress("Scan Worker Finished")
        print(f"[{scan_id}] Scan worker for {target} finished.")

def main():
    global start_time, running, results, total_phases, current_phase_idx

    target = input("Enter IP, Hostname, or CIDR range (e.g., 192.168.1.1 or example.com or 192.168.1.0/24) to scan: ").strip()
    if not target:
        print("No target provided. Exiting.")
        sys.exit(1)

    start_time = time.time()
    current_phase_idx = 0 # Reset for main scan phases

    # Start the Ctrl listener thread
    listener_thread = threading.Thread(target=ctrl_listener, daemon=True)
    listener_thread.start()

    # Worker thread for the main scan
    scan_thread = threading.Thread(target=worker_scan, args=(target, INITIAL_NMAP_ARGS, "initial_full_scan"))
    scan_thread.start()

    try:
        # Keep main thread alive while scan_thread is running
        while running and scan_thread.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Stopping scan...")
        running = False # Signal threads to stop

    # Wait for scan thread to complete or acknowledge stop signal
    scan_thread.join(timeout=10) # Give it some time to gracefully exit
    if scan_thread.is_alive():
        print("Warning: Scan thread did not terminate gracefully.")

    # Wait for listener thread to complete (if it's not daemon, it would block exit)
    # Since it's daemon, it will exit when main thread exits.
    # If not daemon: listener_thread.join()

    total_time = time.time() - start_time
    print(f"\n--- Initial Scan Summary ---")
    print(f"Target: {target}")
    print(f"Scan Arguments: {INITIAL_NMAP_ARGS}")
    print(f"Total time elapsed: {total_time:.2f} seconds.")
    print(f"Hosts found: {len(results)}")

    output_filename = "scanout.json"
    if results:
        try:
            with open(output_filename, "w") as f:
                json.dump(results, f, indent=4)
            print(f"Detailed scan results saved to {output_filename}")
        except Exception as e:
            print(f"Failed to write JSON file '{output_filename}': {e}")
    else:
        print("No scan results to save.")

    print("\n--- Initial Scan Complete ---")

if __name__ == "__main__":
    main()