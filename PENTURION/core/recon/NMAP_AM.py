#version 1
import json
import os
import subprocess
import time
import sys # For sys.exit()

class FactBase:
    """
    Manages the collection of facts derived from scan reports and other inputs.
    """
    def __init__(self):
        self.facts = {}

    def add_fact(self, key, value):
        """Adds or updates a fact."""
        self.facts[key] = value

    def get_fact(self, key, default=None):
        """Retrieves a fact."""
        return self.facts.get(key, default)

    def contains_fact(self, key, value):
        """Checks if a fact exists and has a specific value."""
        return self.facts.get(key) == value

    def fact_list_contains(self, list_key, item):
        """Checks if a fact (which is a list) contains a specific item."""
        fact_list = self.facts.get(list_key)
        return isinstance(fact_list, list) and item in fact_list
        
    def fact_string_contains(self, string_key, substring):
        """Checks if a fact (which is a string) contains a specific substring."""
        fact_string = self.facts.get(string_key)
        return isinstance(fact_string, str) and substring in fact_string

    def __str__(self):
        return json.dumps(self.facts, indent=2)

class Rule:
    """
    Defines a single rule with conditions and actions.
    """
    def __init__(self, rule_id, description, conditions, actions, priority=5, relevant_ports=None):
        self.rule_id = rule_id
        self.description = description
        self.conditions = conditions
        self.actions = actions
        self.priority = priority
        self.relevant_ports = relevant_ports

    def evaluate(self, fact_base: FactBase):
        """
        Evaluates if the rule's conditions are met by the current facts.
        Returns True if all conditions pass, False otherwise.
        """
        for condition in self.conditions:
            fact_key = condition['fact']
            operator = condition['op']
            expected_value = condition['value']
            
            current_value = fact_base.get_fact(fact_key)

            if operator == '==':
                if current_value != expected_value:
                    return False
            elif operator == '!=':
                if current_value == expected_value:
                    return False
            elif operator == 'in': 
                if isinstance(current_value, list):
                    if expected_value not in current_value:
                        return False
                else:
                    if current_value != expected_value:
                        return False
            elif operator == 'contains':
                if isinstance(current_value, list):
                    if expected_value not in current_value:
                        return False
                elif isinstance(current_value, str):
                    if expected_value not in current_value:
                        return False
                else:
                    return False
            elif operator == 'not_contains':
                if isinstance(current_value, list):
                    if expected_value in current_value:
                        return False
                elif isinstance(current_value, str):
                    if expected_value in current_value:
                        return False
                elif expected_value is not None:
                    pass
                else:
                    return False
            elif operator == 'exists':
                if current_value is None:
                    return False
            elif operator == 'not_exists':
                if current_value is not None:
                    return False
            else:
                print(f"Warning: Unknown operator '{operator}' for fact '{fact_key}'. Rule might fail.")
                return False
        return True

    def execute(self, fact_base: FactBase, decisions: list):
        """
        Executes the rule's actions.
        """
        for action in self.actions:
            action_type = action['type']
            if action_type == 'nmap_command':
                cmd = action['command']
                decisions.append({
                    'type': 'nmap_command',
                    'command': cmd,
                    'rule_id': self.rule_id,
                    'relevant_ports': self.relevant_ports
                })
            elif action_type == 'add_fact':
                fact_base.add_fact(action['key'], action['value'])
            elif action_type == 'log':
                decisions.append({
                    'type': 'log',
                    'message': action['message']
                })
            elif action_type == 'update_scan_stage':
                fact_base.add_fact('scan_stage', action['value'])
                decisions.append({
                    'type': 'log',
                    'message': f"Scan stage updated to: {action['value']}"
                })
            else:
                print(f"[ERROR] Unknown action type: {action_type}")

class InferenceEngine:
    """
    The brain of the rule-based system.
    """
    def __init__(self, fact_base: FactBase, rules: list, consolidated_output_file: str):
        self.fact_base = fact_base
        self.rules = sorted(rules, key=lambda r: r.priority, reverse=True)
        self.decisions_made = []
        self.fired_rules = set()
        self.consolidated_output_file = consolidated_output_file
        # Initialize consolidated data with existing scanout.json data
        self.consolidated_nmap_data = [] 
        if os.path.exists(consolidated_output_file) and os.path.getsize(consolidated_output_file) > 0:
            try:
                with open(consolidated_output_file, 'r') as f:
                    self.consolidated_nmap_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Existing consolidated file '{consolidated_output_file}' is not valid JSON. Starting fresh.")
                self.consolidated_nmap_data = []

    def run(self):
        """
        Runs the inference process.
        """
        print("--- Starting Nmap Decision Inference ---")
        
        max_passes = 5
        for i in range(max_passes):
            rules_fired_in_pass = 0
            print(f"\n--- Inference Pass {i+1} (Current Stage: {self.fact_base.get_fact('scan_stage', 'unknown')})---")
            
            current_decisions_for_pass = []
            
            for rule in self.rules:
                if rule.rule_id not in self.fired_rules and rule.evaluate(self.fact_base):
                    rule.execute(self.fact_base, current_decisions_for_pass)
                    self.fired_rules.add(rule.rule_id)
                    rules_fired_in_pass += 1
            
            if not current_decisions_for_pass:
                print(f"No new rules fired in pass {i+1}. Stopping inference.")
                break

            for decision in current_decisions_for_pass:
                self.decisions_made.append(decision) 
                
                if decision['type'] == 'nmap_command':
                    command_template = decision['command']
                    final_nmap_command = command_template

                    if "{fact:open_tcp_ports}" in final_nmap_command:
                        open_ports = self.fact_base.get_fact('open_tcp_ports', [])
                        if open_ports:
                            formatted_ports = ",".join(map(str, open_ports))
                            final_nmap_command = final_nmap_command.replace("{fact:open_tcp_ports}", formatted_ports)
                        else:
                            print(f"[WARNING] Rule {decision['rule_id']}: No open_tcp_ports found. Skipping Nmap command.")
                            continue

                    print(f"\n[Executing Command from {decision['rule_id']}]: {final_nmap_command}")
                    
                    # Use a temporary file for each Nmap command's JSON output
                    temp_output_file = f"temp_nmap_output_{decision['rule_id']}_{int(time.time())}.json"
                    command_with_output = f"{final_nmap_command} -oJ {temp_output_file}"
                    
                    if self.fact_base.get_fact('target_ip') and self.fact_base.get_fact('target_ip') not in command_with_output:
                        command_with_output += f" {self.fact_base.get_fact('target_ip')}"

                    print(f"Running: {command_with_output}")
                    
                    process = subprocess.run(
                        command_with_output, 
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    print(f"Nmap Command Output (stdout):\n{process.stdout}")
                    if process.stderr:
                        print(f"Nmap Command Errors (stderr):\n{process.stderr}")
                    
                    if process.returncode == 0:
                        print(f"Nmap command finished successfully. Output saved to {temp_output_file}")
                        try:
                            time.sleep(0.5) # Give file system a moment

                            if not os.path.exists(temp_output_file) or os.path.getsize(temp_output_file) == 0:
                                print(f"Warning: Temporary Nmap JSON file '{temp_output_file}' not found or empty. Cannot parse.")
                                continue # Skip parsing if file doesn't exist or is empty

                            with open(temp_output_file, 'r') as f:
                                new_nmap_data = json.load(f)
                            print(f"Parsing new scan data from {temp_output_file}...")

                            # Merge new Nmap data into the consolidated list
                            # For simplicity, we'll append host entries.
                            # More sophisticated merging might be needed for complex Nmap outputs
                            # where the same host appears in multiple scans and you want to consolidate
                            # port information, OS detection, etc. within a single host entry.
                            # For now, we assume distinct hosts or new scan data adds to the overall picture.
                            if isinstance(new_nmap_data, list):
                                for host_entry in new_nmap_data:
                                    # This logic needs to be careful about duplicate hosts.
                                    # A more robust merge would iterate through existing hosts and update.
                                    # For simple appending, just add.
                                    self.consolidated_nmap_data.append(host_entry)
                            else:
                                print(f"Warning: Unexpected JSON format from {temp_output_file}. Expected a list.")

                            # Update FactBase with parsed facts
                            temp_facts = parse_nmap_json_report(new_nmap_data)
                            for key, value in temp_facts.facts.items():
                                if key == 'open_tcp_ports' and isinstance(value, list):
                                    existing_ports = self.fact_base.get_fact('open_tcp_ports', [])
                                    self.fact_base.add_fact('open_tcp_ports', sorted(list(set(existing_ports + value))))
                                elif key.startswith('port_') and key.endswith('_state') and self.fact_base.get_fact(key) != 'open':
                                    self.fact_base.add_fact(key, value)
                                elif key.startswith('port_') and (key.endswith('_service') or key.endswith('_version')):
                                    self.fact_base.add_fact(key, value)
                                elif key == 'target_os' and self.fact_base.get_fact('target_os') is None:
                                    self.fact_base.add_fact(key, value)
                                elif key == 'initial_scripts_run' and self.fact_base.get_fact('initial_scripts_run') is None:
                                    self.fact_base.add_fact(key, value)
                                else:
                                    self.fact_base.add_fact(key, value)
                            print("FactBase updated with new Nmap scan results.")

                        except Exception as parse_e:
                            print(f"Error parsing temporary Nmap JSON output {temp_output_file}: {parse_e}")
                        finally:
                            # Clean up the temporary file
                            if os.path.exists(temp_output_file):
                                os.remove(temp_output_file)
                                print(f"Cleaned up temporary file: {temp_output_file}")
                    else:
                        print(f"Nmap command exited with code {process.returncode}. Check output above for details.")

       # except FileNotFoundError:
        #                    print(f"Error: Nmap command not found. Make sure Nmap is installed and in your PATH.")
         #       except Exception as e:
          #          print(f"An error occurred while executing Nmap command: {e}")
           #     elif decision['type'] == 'log':
            #        print(f"Log: {decision['message']}")

        print("\n--- Inference Complete ---")
        if not self.decisions_made:
            print("No specific Nmap commands or actions recommended based on current rules and facts.")
        else:
            print("\nSummary of Recommended/Executed Actions:")
            for decision in self.decisions_made:
                if decision['type'] == 'nmap_command':
                    ports_info = ""
                    if decision['relevant_ports'] is None or decision['relevant_ports'] == "Host":
                        ports_info = "Host"
                    elif isinstance(decision['relevant_ports'], list):
                        if len(decision['relevant_ports']) == 1:
                            ports_info = str(decision['relevant_ports'][0])
                        else:
                            ports_info = f"Ports {','.join(map(str, decision['relevant_ports']))}"
                    elif isinstance(decision['relevant_ports'], str):
                        ports_info = decision['relevant_ports']

                    print(f"Port: {ports_info:<15} Command: {decision['command']:<60} Reason: {decision['rule_id']}")
                elif decision['type'] == 'log':
                    print(f"Log: {decision['message']}")
        
        # --- Write consolidated Nmap data to a single file at the end ---
        if self.consolidated_nmap_data:
            try:
                with open(self.consolidated_output_file, 'w') as f:
                    json.dump(self.consolidated_nmap_data, f, indent=2)
                print(f"\nAll Nmap scan results consolidated and saved to: {self.consolidated_output_file}")
            except Exception as e:
                print(f"Error writing consolidated Nmap data to file {self.consolidated_output_file}: {e}")
        else:
            print(f"\nNo Nmap scan results to consolidate and save to {self.consolidated_output_file}.")


def parse_nmap_json_report(json_report_data):
    """
    Parses a simplified Nmap JSON report into a FactBase.
    This function can be called multiple times to update facts.
    """
    facts = FactBase()
    
    if not isinstance(json_report_data, list) or not json_report_data:
        # print("Invalid Nmap report format. Expected a list of host objects.")
        return facts

    # It's possible a scan returns no 'up' hosts, resulting in an empty list.
    if len(json_report_data) == 0:
        # print("Nmap report is empty (no hosts found).")
        return facts

    # Focus on the first host for general facts, or iterate if multiple hosts are expected per scan
    host_data = json_report_data[0] 

    host_ip = host_data.get('host')
    hostname = host_data.get('hostname')
    host_state = host_data.get('state')

    if host_ip:
        facts.add_fact('target_ip', host_ip)
    if hostname:
        facts.add_fact('target_hostname', hostname)
    if host_state:
        facts.add_fact('host_status', host_state)

    open_ports_list = []
    # Check if 'protocols' key exists before accessing
    if 'protocols' in host_data and 'tcp' in host_data['protocols']:
        for port_entry in host_data['protocols']['tcp']:
            port = port_entry.get('port')
            state = port_entry.get('state')
            service = port_entry.get('service')
            version = port_entry.get('version')

            if state == 'open':
                open_ports_list.append(port)
                facts.add_fact(f'port_{port}_state', 'open')
                if service:
                    facts.add_fact(f'port_{port}_service', service)
                if version:
                    facts.add_fact(f'port_{port}_version', version)
            elif state == 'closed' or state == 'filtered':
                facts.add_fact(f'port_{port}_state', state)
                
    facts.add_fact('open_tcp_ports', sorted(list(set(open_ports_list))))

    if 'os' in host_data and len(host_data['os']) > 0:
        facts.add_fact('target_os', host_data['os'][0]['name'])
    if 'hostscript' in host_data and len(host_data['hostscript']) > 0:
        facts.add_fact('initial_scripts_run', True)
        for script_result in host_data['hostscript']:
            script_id = script_result.get('id')
            script_output = script_result.get('output')
            if script_id and script_output:
                facts.add_fact(f'script_output_{script_id}', script_output)
    
    scaninfo = host_data.get('scaninfo', {})
    if 'type' in scaninfo and 'services' in scaninfo:
        facts.add_fact('initial_scan_type', f"{scaninfo['type']}_{scaninfo['services']}")

    return facts

# --- Define the Rules (No changes needed here based on this request) ---
def define_nmap_rules(target_ip):
    rules = []

    rules.append(Rule(
        rule_id="R000_INITIAL_SCAN_REQUIRED",
        description="Trigger initial comprehensive Nmap scan if no scan data exists.",
        conditions=[
            {'fact': 'target_ip', 'op': 'not_exists', 'value': None},
            {'fact': 'scan_stage', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'log', 'message': f"No initial scan data found. Triggering SUBSCAN.py for {target_ip}."},
            {'type': 'add_fact', 'key': 'initial_scan_triggered', 'value': True},
            {'type': 'update_scan_stage', 'value': 'initial_discovery_complete'}
        ],
        priority=100,
        relevant_ports="N/A"
    ))

    rules.append(Rule(
        rule_id="R001_HOST_IS_DOWN",
        description="If host is down, no further scanning.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'initial_discovery_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'down'}
        ],
        actions=[
            {'type': 'log', 'message': f"Host {target_ip} is reported as down. No further action."}
        ],
        priority=90,
        relevant_ports="N/A"
    ))
    
    rules.append(Rule(
        rule_id="R002_NO_OPEN_PORTS",
        description="If host is up but no open ports found, suggest re-scan or termination.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'initial_discovery_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': '==', 'value': []}
        ],
        actions=[
            {'type': 'log', 'message': f"Host {target_ip} is up but no open TCP ports found. Consider a full port scan (nmap -p- {target_ip}) or UDP scan."}
        ],
        priority=85,
        relevant_ports="N/A"
    ))

    rules.append(Rule(
        rule_id="R300_SERVICE_VERSIONING_SUPPLEMENTAL",
        description="Run comprehensive service version detection if not fully done by initial scan.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'initial_discovery_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': '!=', 'value': []},
            {'fact': 'full_service_scan_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -sV -p {{fact:open_tcp_ports}} {target_ip}"},
            {'type': 'add_fact', 'key': 'full_service_scan_done', 'value': True},
            {'type': 'update_scan_stage', 'value': 'detailed_service_analysis'}
        ],
        priority=70,
        relevant_ports="All Open Ports"
    ))

    rules.append(Rule(
        rule_id="R400_GENERAL_VULN_SCRIPTS_SUPPLEMENTAL",
        description="Run general vulnerability scripts if not covered by initial scan.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'detailed_service_analysis'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': '!=', 'value': []},
            {'fact': 'general_vuln_scripts_run', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap --script 'vuln' -p {{fact:open_tcp_ports}} {target_ip}"},
            {'type': 'add_fact', 'key': 'general_vuln_scripts_run', 'value': True},
            {'type': 'update_scan_stage', 'value': 'vulnerability_identification_complete'}
        ],
        priority=70,
        relevant_ports="All Open Ports"
    ))

    rules.append(Rule(
        rule_id="R100_FTP_ANON_CHECK",
        description="Check for anonymous FTP login if port 21 is open.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 21},
            {'fact': 'port_21_service', 'op': 'contains', 'value': 'ftp'},
            {'fact': 'ftp_anon_check_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 21 --script ftp-anon {target_ip}"},
            {'type': 'add_fact', 'key': 'ftp_anon_check_done', 'value': True}
        ],
        priority=75,
        relevant_ports=[21]
    ))

    rules.append(Rule(
        rule_id="R101_HTTP_ENUMERATION",
        description="Run common web enumeration scripts for open HTTP/HTTPS ports.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 80},
            {'fact': 'http_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 80,443,8443 --script http-enum,http-title,http-headers,http-server-header {target_ip}"},
            {'type': 'add_fact', 'key': 'http_enum_done', 'value': True}
        ],
        priority=65,
        relevant_ports=[80, 443, 8443]
    ))

    rules.append(Rule(
        rule_id="R102_SSL_TLS_VULN_CHECK",
        description="Run SSL/TLS vulnerability scripts for open HTTPS ports.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 443},
            {'fact': 'port_443_service', 'op': 'contains', 'value': 'https'},
            {'fact': 'ssl_tls_check_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 443 --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,tls-sni {target_ip}"},
            {'type': 'add_fact', 'key': 'ssl_tls_check_done', 'value': True}
        ],
        priority=80,
        relevant_ports=[443]
    ))
    
    rules.append(Rule(
        rule_id="R103_SMB_ENUMERATION",
        description="Check for SMB enumeration if port 445 is open.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 445},
            {'fact': 'port_445_service', 'op': 'contains', 'value': 'microsoft-ds'},
            {'fact': 'smb_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 {target_ip}"},
            {'type': 'add_fact', 'key': 'smb_enum_done', 'value': True}
        ],
        priority=85,
        relevant_ports=[445]
    ))

    rules.append(Rule(
        rule_id="R500_EXPLOIT_METASPLOIT_FTP_ANON",
        description="Suggest Metasploit for anonymous FTP login if found.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'port_21_state', 'op': '==', 'value': 'open'},
            {'fact': 'port_21_service', 'op': 'contains', 'value': 'ftp'},
            {'fact': 'script_output_ftp-anon', 'op': 'contains', 'value': 'Anonymous FTP login allowed'}
        ],
        actions=[
            {'type': 'log', 'message': f"[EXPLOIT SUGGESTION] Anonymous FTP access on {target_ip}:21. Consider using Metasploit 'ftp_login' module or manual exploitation."}
        ],
        priority=79,
        relevant_ports=[21]
    ))

    rules.append(Rule(
        rule_id="R501_EXPLOIT_SMB_MS17_010",
        description="Suggest Metasploit for EternalBlue (MS17-010) if vulnerable.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'port_445_state', 'op': '==', 'value': 'open'},
            {'fact': 'script_output_smb-vuln-ms17-010', 'op': 'contains', 'value': 'VULNERABLE'}
        ],
        actions=[
            {'type': 'log', 'message': f"[EXPLOIT SUGGESTION] Host {target_ip} is vulnerable to MS17-010 (EternalBlue) on port 445. Consider using Metasploit 'exploit/windows/smb/ms17_010_eternalblue' or 'exploit/windows/smb/ms17_010_psexec'."}
        ],
        priority=60,
        relevant_ports=[445]
    ))

    rules.append(Rule(
        rule_id="R502_EXPLOIT_HTTP_COMMON_VULNS",
        description="Suggest general web exploitation if HTTP vulns are detected.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 80},
            {'fact': 'script_output_http-enum', 'op': 'exists', 'value': None}
        ],
        actions=[
            {'type': 'log', 'message': f"[EXPLOIT SUGGESTION] Web server on {target_ip}:80 likely has vulnerabilities. Consider using Burp Suite, OWASP ZAP, or specific web exploit frameworks."}
        ],
        priority=20,
        relevant_ports=[80,443]
    ))

    rules.append(Rule(
        rule_id="R900_SCAN_PHASE_COMPLETE",
        description="Indicate that the active scanning phase is considered complete.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'full_service_scan_done', 'op': '==', 'value': True},
            {'fact': 'general_vuln_scripts_run', 'op': '==', 'value': True},
            {'fact': 'ftp_anon_check_done', 'op': 'exists', 'value': None},
            {'fact': 'http_enum_done', 'op': 'exists', 'value': None},
            {'fact': 'ssl_tls_check_done', 'op': 'exists', 'value': None},
            {'fact': 'smb_enum_done', 'op': 'exists', 'value': None},
            {'fact': 'final_scan_stage_set', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'update_scan_stage', 'value': 'exploit_consideration_phase'},
            {'type': 'add_fact', 'key': 'final_scan_stage_set', 'value': True},
            {'type': 'log', 'message': "All active scanning rules have been processed. Proceeding to exploit consideration."}
        ],
        priority=10,
        relevant_ports="N/A"
    ))

    return rules

# --- Main Execution ---
if __name__ == "__main__":
    initial_scan_file_path = "scanout.json" # Initial scan file
    consolidated_output_file_path = "consolidated_nmap_results.json" # New consolidated file

    initial_target_ip = None

    # --- Step 1: Check for initial scan data or trigger nmapscan.py ---
    if not os.path.exists(initial_scan_file_path) or os.path.getsize(initial_scan_file_path) == 0:
        print(f"'{initial_scan_file_path}' not found or is empty. Initial scan required.")
        target_input = input("Enter target IP or URL for the initial scan: ").strip()
        if not target_input:
            print("No target provided. Exiting.")
            sys.exit(1)
        initial_target_ip = target_input
        
        print(f"Running initial scan using SUBSCAN.py against {initial_target_ip}...")
        try:
            process = subprocess.run(
                ["python3", "SUBSCAN.py"],
                input=f"{initial_target_ip}\n",
                capture_output=True,
                text=True,
                check=False
            )
            print(f"\nSUBSCAN.py stdout:\n{process.stdout}")
            if process.stderr:
                print(f"SUBSCAN.py stderr:\n{process.stderr}")

            if process.returncode != 0:
                print(f"Warning: SUBSCAN.py exited with code {process.returncode}. Please check its output for errors.")
            
            time.sleep(1)

            if not os.path.exists(initial_scan_file_path) or os.path.getsize(initial_scan_file_path) == 0:
                print(f"Error: SUBSCAN.py failed to create a valid '{initial_scan_file_path}'. Exiting.")
                sys.exit(1)
            else:
                print(f"Initial scan data successfully generated in '{initial_scan_file_path}'.")
        except FileNotFoundError:
            print("Error: SUBSCAN.py not found. Make sure it's in the same directory.")
            sys.exit(1)
        except Exception as e:
            print(f"An error occurred while running SUBSCAN.py: {e}")
            sys.exit(1)
            
    # --- Step 2: Load initial facts and populate consolidated data ---
    nmap_report_data = None
    try:
        with open(initial_scan_file_path, 'r') as f:
            nmap_report_data = json.load(f)
        print(f"Successfully loaded scan data from {initial_scan_file_path}")
    except json.JSONDecodeError:
        print(f"Error: {initial_scan_file_path} contains invalid JSON. Please check the file.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading {initial_scan_file_path}: {e}")
        sys.exit(1)

    initial_facts = parse_nmap_json_report(nmap_report_data)
    
    if not initial_facts.get_fact('target_ip') and initial_target_ip:
        initial_facts.add_fact('target_ip', initial_target_ip)

    target_ip = initial_facts.get_fact('target_ip')
    if not target_ip:
        print("Error: Could not determine target IP from the report. Exiting.")
        sys.exit(1)
    
    if not initial_facts.get_fact('scan_stage'):
        initial_facts.add_fact('scan_stage', 'initial_discovery_complete')

    print("\nInitial Facts for {}:".format(target_ip))
    print(initial_facts)

    # Initialize the consolidated_nmap_results.json with the initial scan data
    # This assumes scanout.json is the FIRST set of results.
    try:
        with open(consolidated_output_file_path, 'w') as f:
            json.dump(nmap_report_data, f, indent=2)
        print(f"Initial scan data written to consolidated file: {consolidated_output_file_path}")
    except Exception as e:
        print(f"Error writing initial scan data to consolidated file: {e}")


    # --- Step 3: Initialize and run the Inference Engine ---
    rules = define_nmap_rules(target_ip)
    # Pass the consolidated output file path to the InferenceEngine
    engine = InferenceEngine(initial_facts, rules, consolidated_output_file_path)
    engine.run()