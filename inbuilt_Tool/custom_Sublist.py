import subprocess
import requests
import json
import os

def run_sublist3r(domain):
    print(f"[+] Running Sublist3r for {domain}")
    try:
        result = subprocess.run(
            ["python3", "Sublist3r/sublist3r.py", "-d", domain],
            capture_output=True, text=True
        )
        lines = result.stdout.splitlines()
        found = {line.strip() for line in lines if domain in line and not line.startswith("[-]")}
        print(f"[+] Sublist3r found {len(found)} subdomains.")
        return found
    except Exception as e:
        print(f"[!] Sublist3r error: {e}")
        return set()

def run_crtsh_enum(domain):
    print(f"[+] Querying crt.sh for {domain}")
    found = set()
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                for sub in entry['name_value'].splitlines():
                    if domain in sub:
                        found.add(sub.strip().lower())
            print(f"[+] crt.sh found {len(found)} subdomains.")
        else:
            print(f"[!] crt.sh returned status code: {response.status_code}")
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
    return found

def run_subfinder(domain):
    print(f"[+] Running subfinder for {domain}")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True, text=True
        )
        subs = {line.strip() for line in result.stdout.splitlines() if domain in line}
        print(f"[+] subfinder found {len(subs)} subdomains.")
        return subs
    except Exception as e:
        print(f"[!] subfinder error: {e}")
        return set()

def verify_subdomains(subdomains):
    print("[+] Verifying subdomains...")
    alive = []
    for sub in sorted(subdomains):
        url = f"http://{sub}"
        try:
            r = requests.get(url, timeout=4)
            if r.status_code < 400:
                print(f"[+] Alive: {url}")
                alive.append(url)
        except:
            continue
    print(f"[+] {len(alive)} subdomains are alive.")
    return alive

def export_to_json(domain, all_subs, live_subs):
    print("[+] Exporting to JSON...")
    result = {
        "tool_version": "2.0",
        "domain": domain,
        "total_found": len(all_subs),
        "live_count": len(live_subs),
        "all_subdomains": sorted(all_subs),
        "live_subdomains": sorted(live_subs)
    }

    filename = f"{domain.replace('.', '_')}_results.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)
    print(f"[+] JSON saved to {filename}")

def main():
    print("==== Subdomain Enumeration Tool v2.0 ====")
    domain = input("Enter the domain (e.g., example.com): ").strip()

    s1 = run_sublist3r(domain)
    s2 = run_crtsh_enum(domain)
    s3 = run_subfinder(domain)

    all_subs = s1.union(s2).union(s3)
    print(f"[+] Total unique subdomains found: {len(all_subs)}")

    live_subs = verify_subdomains(all_subs)
    export_to_json(domain, all_subs, live_subs)

if __name__ == "__main__":
    main()

