import nmap
import threading
import time
import sys
import termios
import tty
import json
from queue import Queue

# Globals
scanned_ports = 0
total_ports = 1000  # Top 1000 TCP ports
start_time = None
running = True
lock = threading.Lock()
results = []

def getch():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def ctrl_listener():
    global running, scanned_ports, start_time, total_ports
    while running:
        ch = getch()
        if ch == '\x14':  # Ctrl+T
            elapsed = time.time() - start_time
            with lock:
                scanned = scanned_ports
            if scanned > 0:
                rate = elapsed / scanned
                remaining_ports = total_ports - scanned
                est_remaining = remaining_ports * rate
                percent = (scanned / total_ports) * 100
            else:
                est_remaining = 0
                percent = 0
            print(f"\n[Ctrl+T] Elapsed: {elapsed:.1f}s | Estimated Remaining: {est_remaining:.1f}s | Completed: {percent:.2f}%\n")
        elif ch == '\x11':  # Ctrl+Q
            print("\n[Ctrl+Q] Exit signal received. Stopping scan...\n")
            running = False
            break
        time.sleep(0.1)

def extract_scan_data(nm, target):
    extracted = []
    for host in nm.all_hosts():
        host_data = {
            "host": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "scaninfo": nm.scaninfo(),
            "protocols": {},
            "os": [],
            "hostscript": [],
            "traceroute": []
        }

        for proto in nm[host].all_protocols():
            ports = []
            for port in sorted(nm[host][proto].keys()):
                pdata = nm[host][proto][port]
                ports.append({
                    "port": port,
                    "state": pdata['state'],
                    "service": pdata['name'],
                    "version": pdata.get('version', 'N/A')
                })
            host_data["protocols"][proto] = ports

        if 'osmatch' in nm[host]:
            for osmatch in nm[host]['osmatch']:
                match_data = {
                    "name": osmatch['name'],
                    "accuracy": osmatch['accuracy'],
                    "osclass": []
                }
                for osclass in osmatch.get('osclass', []):
                    match_data['osclass'].append({
                        "type": osclass['type'],
                        "vendor": osclass['vendor'],
                        "osfamily": osclass['osfamily'],
                        "cpe": osclass.get('cpe', [])
                    })
                host_data["os"].append(match_data)

        if 'hostscript' in nm[host]:
            for script in nm[host]['hostscript']:
                host_data["hostscript"].append({
                    "id": script['id'],
                    "output": script['output']
                })

        if 'traceroute' in nm[host]:
            for hop in nm[host]['traceroute']:
                host_data["traceroute"].append({
                    "hop": hop['hop'],
                    "address": hop['address'],
                    "rtt": hop['rtt']
                })

        extracted.append(host_data)
    return extracted

def worker_scan(target, task_queue):
    global scanned_ports, running, results
    nm = nmap.PortScanner()
    args = "-sV -O -sC --traceroute"

    while running:
        try:
            task_queue.get_nowait()
        except:
            break

        print(f"Scanning top 1000 TCP ports...")
        try:
            nm.scan(target, arguments=args)
            parsed_data = extract_scan_data(nm, target)
            with lock:
                results.extend(parsed_data)
        except Exception as e:
            print(f"Error during scan: {e}")

        with lock:
            scanned_ports = total_ports

        task_queue.task_done()

def main():
    global start_time, running, results

    target = input("Enter IP or URL to scan: ").strip()
    start_time = time.time()

    task_queue = Queue()
    task_queue.put("scan-top-1000")  # Only one task

    listener_thread = threading.Thread(target=ctrl_listener, daemon=True)
    listener_thread.start()

    num_threads = 1  # Only 1 thread needed for one scan task
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker_scan, args=(target, task_queue))
        t.start()
        threads.append(t)

    try:
        while running and any(t.is_alive() for t in threads):
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt received. Stopping scan...")
        running = False

    for t in threads:
        t.join()

    running = False
    listener_thread.join()

    total_time = time.time() - start_time
    print(f"\nScan finished in {total_time:.2f} seconds.")
    print(f"Total ports scanned: {scanned_ports} / {total_ports}")

    try:
        with open("scanout.json", "w") as f:
            json.dump(results, f, indent=4)
        print("Results saved to scanout.json")
    except Exception as e:
        print(f"Failed to write JSON file: {e}")

if __name__ == "__main__":
    main()
