from colorama import Fore, Style, init
import random
import subprocess

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

# Example usage
if __name__ == "__main__":
    print_banner()
    try:
      print(Fore.GREEN + Style.BRIGHT + "\n [*] (main2.py)NMAP SCANING  processing .......\n")
      subprocess.run(["python3","/home/arunexploit/Penturion/AImodel/main.py"])
      
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f" [!] Error running NMAPSCAN.py: {e}")
