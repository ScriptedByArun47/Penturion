# SUBSCAN.py - Updated with user-defined INITIAL_NMAP_ARGS for comprehensive initial Nmap scan
# and crucial directory creation logic.

import sys
import subprocess
import os
import time
import xml.etree.ElementTree as ET # Import for potential XML validation

# User-defined Nmap initial arguments
# -sS: SYN scan
# -sV: Service version detection
# -O: OS detection
# -sC: Default scripts (equivalent to --script=default)
# -T4: Aggressive timing template
# --top-ports 1000: Scans the 1000 most common ports
# --traceroute: Performs a traceroute to the target
# --reason: Displays the reason a port is in a particular state
# --version-intensity 9: Sets version scan intensity to 9 (more aggressive)
INITIAL_NMAP_ARGS = "-sS -sV -O -sC -T4 --top-ports 1000 --traceroute --reason --version-intensity 9"

def run_nmap_scan(target_ip, output_file="scanout.xml"):
    """
    Runs a basic Nmap scan and outputs results to an XML file.
    Ensures the output directory exists before running Nmap.
    """
    print(f"[{os.path.basename(__file__)}] Starting Nmap scan for {target_ip}...")
    
    # --- CRUCIAL ADDITION: Ensure the output directory exists ---
    output_directory = os.path.dirname(output_file)
    if output_directory and not os.path.exists(output_directory):
        try:
            os.makedirs(output_directory, exist_ok=True) # exist_ok=True prevents error if it already exists
            print(f"[{os.path.basename(__file__)}] Created output directory: {output_directory}")
        except OSError as e:
            print(f"[{os.path.basename(__file__)}] Error creating directory {output_directory}: {e}", file=sys.stderr)
            return False # Indicate failure if directory cannot be created
    # -----------------------------------------------------------

    # Split the initial Nmap args string into a list, filtering out any empty strings
    args_list = [arg for arg in INITIAL_NMAP_ARGS.split(' ') if arg]

    # Construct the final Nmap command list
    nmap_command = ["nmap"] # Nmap is expected to be in PATH, otherwise specify full path (e.g., "/usr/bin/nmap")
    nmap_command.extend(args_list) # Add all the flags from the user's string
    
    # Add the XML output flag and file (Nmap expects filename directly after -oX)
    nmap_command.append("-oX")
    nmap_command.append(output_file)
    
    # Add the target IP (always the last argument for Nmap)
    nmap_command.append(target_ip)
    
    print(f"[{os.path.basename(__file__)}] Executing Nmap command: {' '.join(nmap_command)}")
    print(f"[{os.path.basename(__file__)}] Expected output file path: {output_file}")

    try:
        process = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            check=False # Do not raise an exception for non-zero exit codes, we handle them
        )
        
        print(f"[{os.path.basename(__file__)}] Nmap stdout:\n{process.stdout}")
        if process.stderr:
            print(f"[{os.path.basename(__file__)}] Nmap stderr:\n{process.stderr}")

        if process.returncode != 0:
            print(f"[{os.path.basename(__file__)}] Nmap command exited with code {process.returncode}. This might indicate an issue, but the XML file might still be partially created.")
            
        # Give a small moment for file system to catch up
        time.sleep(0.5) 

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"[{os.path.basename(__file__)}] Nmap scan completed. Output saved to {output_file}")
            try:
                # Basic XML validation to ensure it's not corrupted
                ET.parse(output_file) 
                return True
            except ET.ParseError:
                print(f"[{os.path.basename(__file__)}] Error: Output file '{output_file}' is not valid XML. Deleting corrupted file.")
                os.remove(output_file) # Remove corrupted file
                return False
        else:
            print(f"[{os.path.basename(__file__)}] Error: Nmap output file '{output_file}' was not created or is empty.")
            return False

    except FileNotFoundError:
        print(f"[{os.path.basename(__file__)}] Error: Nmap not found. Please ensure Nmap is installed and in your system's PATH, or provide the full path to the nmap executable instead of just 'nmap'.")
        return False
    except Exception as e:
        print(f"[{os.path.basename(__file__)}] An unexpected error occurred during Nmap execution: {e}")
        return False

if __name__ == "__main__":
    target_ip = sys.stdin.readline().strip()

    if not target_ip:
        print(f"[{os.path.basename(__file__)}] Error: No target IP received via stdin. Exiting.")
        sys.exit(1)

    # The hardcoded path for output within SUBSCAN.py
    # If main.py calls this, ensure main.py passes "/output/scanout.xml"
    if not run_nmap_scan(target_ip, "output/scanout.xml"):
        sys.exit(1)