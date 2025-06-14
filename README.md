# 🛡️ Penturion

**Automated Web Pentesting Framework**  
by [Arun Kumar L](https://github.com/ScriptedByArun47)

---

## 🔍 Overview

**Penturion** is an all-in-one automated web penetration testing tool that streamlines every phase of pentesting — from reconnaissance to reporting. It is designed to assist ethical hackers, bug bounty hunters, and cybersecurity enthusiasts by automating repetitive tasks and generating structured output.

---

## 🚀 Features

- ✅ **Reconnaissance:** Subdomain discovery, DNS enumeration, WHOIS, etc.
- ✅ **Scanning:** Port scanning, service detection, web fingerprinting.
- ✅ **Exploitation:** Identifies and automates common web-based attacks.
- ✅ **Bypass:** WAF/403/401 bypass techniques.
- ✅ **Reporting:** Clean JSON output for logs and integration.
- ✅ **Modes:**  
  - `Black Mode` → Passive & active recon  
  - `Gray Mode` → Recon + Exploitation  

---

## 🧰 Built With

- **Language:** Python ,Go & C++
- **Libraries:** `sublist3r`, `httpx`, `nmap`, `argparse`, `colorama`, `json`
- **Tools Integrated:** Subfinder, DNSx, Nmap, etc.
- **Special Modules:**  
  - `inbuilt_Tool/` → Internal scanning utilities  
  - `AImodel/` → AI-assisted analysis and suggestions

---

## 🖥️ Usage

```bash
# Clone the repo
git clone https://github.com/ScriptedByArun47/Penturion.git
cd Penturion

# Run the main tool
python3 automation_main.py --domain example.com --mode black
