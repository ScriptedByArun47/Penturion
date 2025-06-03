#!/usr/bin/env python3
import json
import subprocess
import sys
import os

def run_nmap_scan(target):
    """
    Runs a comprehensive Nmap scan (-sV for version, -sC for default scripts, -O for OS detection)
    and returns the parsed JSON output from Nmap.
    """
    # Nmap command: nmap -sV -sC -O <target> -oJ -
    # -sV: Service/Version detection
    # -sC: Default NSE scripts
    # -O:  OS detection (may require root/administrator privileges)
    # -oJ -: Output JSON to stdout
    nmap_command = ["nmap", "-sV", "-sC", "-O", target, "-oJ", "-"]
    
    print(f"Executing Nmap command: {' '.join(nmap_command)}", file=sys.stderr)
    
    try:
        process = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            check=False # We'll check returncode manually to handle Nmap's specific exit codes
        )

        if process.returncode != 0:
            # Nmap can exit non-zero for various reasons (e.g., host down, privileges for -O)
            # We still want to try parsing stdout if it contains JSON.
            print(f"Nmap exited with code {process.returncode}.", file=sys.stderr)
            if process.stderr:
                print(f"Nmap stderr:\n{process.stderr.strip()}", file=sys.stderr)
        
        if not process.stdout:
            print("Nmap produced no output.", file=sys.stderr)
            return None

        nmap_output_json = json.loads(process.stdout)
        return nmap_output_json
        
    except FileNotFoundError:
        print("Error: Nmap command not found. Make sure Nmap is installed and in your PATH.", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding Nmap JSON output: {e}", file=sys.stderr)
        print(f"Nmap raw stdout that caused error:\n{process.stdout[:500]}...", file=sys.stderr) # Print a snippet
        return None
    except Exception as e:
        print(f"An unexpected error occurred during Nmap execution: {e}", file=sys.stderr)
        return None

def transform_nmap_json_to_host_list(nmap_data):
    """
    Transforms Nmap's standard JSON output (a dictionary) into a list of host objects.
    This is the format expected by the main script's parser.
    """
    if not nmap_data or "hosts" not in nmap_data:
        # 'hosts' is a key in Nmap's JSON output containing a list of scanned hosts.
        return [] 
    return nmap_data["hosts"]

if __name__ == "__main__":
    target_host = None
    # Allow passing target as a command-line argument for direct testing
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
        print(f"Target received from command line: {target_host}", file=sys.stderr)
    else:
        # Read target from stdin (as expected by your main script)
        print("Waiting for target IP/hostname from stdin...", file=sys.stderr)
        try:
            target_host = sys.stdin.readline().strip()
        except KeyboardInterrupt:
            print("\nInput cancelled by user.", file=sys.stderr)
            sys.exit(1)
            
        if not target_host:
            print("No target received from stdin. Exiting.", file=sys.stderr)
            sys.exit(1)
        print(f"Target received from stdin: {target_host}", file=sys.stderr)

    nmap_json_output = run_nmap_scan(target_host)
    output_filename = "scanout.json"

    if nmap_json_output:
        # Transform the raw Nmap JSON to the list of hosts format
        simplified_host_list = transform_nmap_json_to_host_list(nmap_json_output)
        
        if not simplified_host_list:
            print(f"No host data extracted from Nmap output for {target_host}. "
                  f"{output_filename} will contain an empty list.", file=sys.stderr)
        
        try:
            with open(output_filename, 'w') as f:
                json.dump(simplified_host_list, f, indent=2)
            print(f"Nmap scan results for {target_host} processed and saved to {output_filename}", file=sys.stderr)
            sys.exit(0) # Success
        except IOError as e:
            print(f"Error writing to {output_filename}: {e}", file=sys.stderr)
            sys.exit(1) # Failure
        except Exception as e: # Catch any other unexpected error during writing
            print(f"An unexpected error occurred while writing {output_filename}: {e}", file=sys.stderr)
            sys.exit(1) # Failure
    else:
        print(f"Failed to get Nmap scan data for {target_host}. "
              f"Attempting to write an empty list to {output_filename} to prevent looping.", file=sys.stderr)
        # Write an empty list to scanout.json to ensure the main script
        # doesn't repeatedly try to run nmapscan.py if it fails consistently.
        try:
            with open(output_filename, 'w') as f:
                json.dump([], f)
            print(f"Wrote empty list to {output_filename}.", file=sys.stderr)
        except IOError as e:
            print(f"Error writing empty list to {output_filename}: {e}", file=sys.stderr)
        sys.exit(1) # Indicate failure to the calling process