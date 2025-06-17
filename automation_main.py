from colorama import Fore, Style, init
import random
import subprocess
import os,json

init(autoreset=True)

def print_banner():
    
    ascii_art = f"""
{Fore.RED}{Style.BRIGHT}

     ____    ______    _   _    _____   _   _    _____    ______      __    _   _
    | __ \  |  ____|  | \ | |  |_  __| | | | |  |  __ \  |__  __|   / _ \  | \ | |
    |/_/ /  |  __|    |  \| |    | |   | | | |  | |__) |    | |    | | | | |  \| |
    |, _/   | |____   | |\  |    | |   | |_| |  |  _  /   __| |_   | |_| | | |\  |
    |_|     |______|  |_| \_|    |_|    \___/   |_| \_\  |______|   \ __/  |_| \_|
                                                            
                               
{Fore.LIGHTCYAN_EX}{Style.BRIGHT}         Automated Web Pentesting Framework
{Fore.YELLOW}      ↪ Recon | Scaning | Exploit | Bypass | Report
{Fore.GREEN}                                                                     Author : ArunKumar L
{Fore.MAGENTA}                         GitHub  : https://github.com/ScriptedByArun47
{Style.RESET_ALL}
""" 
    quote = random.choice([
        "“The quieter you become, the more you are able to hear.”",
        "“Hacking is not a crime. It’s a skill.”",
        "“Recon is not optional. It’s the war plan.”",
        "“Behind every firewall is a misconfigured hope.”",
        "“Automation doesn't replace skill — it empowers it.”"
    ])

    print(ascii_art)
    print(Fore.GREEN + Style.BRIGHT + f" [*] {quote}")
    print(Fore.MAGENTA + "-" * 65 + Style.RESET_ALL)

def get_domain_for_ip(ip, json_file_path):
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
            hosts = data.get("nmaprun", {}).get("host", [])
            if isinstance(hosts, dict):
                hosts = [hosts]  # Normalize if it's a single host as dict

            for host in hosts:
                addresses = host.get("addresses", [])
                if isinstance(addresses, dict):
                    addresses = [addresses]

                for addr in addresses:
                    if addr.get("addr") == ip:
                        hostnames = host.get("hostnames", [])
                        if hostnames:
                            return hostnames[0].get("name")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f" [!] Error reading result.json: {e}")
    return None


if __name__ == "__main__":
    print_banner()
    DEBUG_MODE = True # Set to True for debugging, False for production
    if not DEBUG_MODE:
        try:
            print(Fore.GREEN + Style.BRIGHT + "\n [*] (main2.py)NMAP SCANING  processing .......\n")
            subprocess.run(["python3","/home/arunexploit/Penturion/AImodel/main.py"])
            print(Fore.GREEN + Style.BRIGHT + "\n [*] (main2.py)NMAP SCANING completed successfully!\n")
            
                
        
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f" [!] Error running NMAPSCAN.py: {e}")
        
    try:
    # Read the target IP from file
        with open("output/penturion_target.txt", "r") as f:
            target_ip = f.read().strip()

        # Map IP → domain 

        target_domain = get_domain_for_ip(target_ip, "output/result.json")

        if not target_domain:
            print(Fore.YELLOW + Style.BRIGHT + f" [!] No domain name found for IP {target_ip} in result.json. Skipping subdomain scan.")
        else:
            os.makedirs("output", exist_ok=True)
            print(Fore.GREEN + Style.BRIGHT + f"\n [*] (subbrute.py) processing against domain: {target_domain}\n")

            # Run subbrute.py
            subprocess.run([
             "python3",
             "inbuilt_Tool/subbrute/subbrute.py",
             "-o", "output/subbrute_output.txt",
            "cyfotok.com"  # Positional argument — the target domain
            ])


            print(Fore.GREEN + Style.BRIGHT + "\n [*] (subbrute.py) completed successfully!\n")

    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + " [!] File 'output/penturion_target.txt' not found.")
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f" [!] Error: {e}")