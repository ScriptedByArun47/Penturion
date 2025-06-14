#version 2 - Advanced Scan Combination
import json
import os
import subprocess
import time
import sys

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
        Supports 'and' and 'or' logic within conditions.
        Returns True if all 'and' groups pass, and at least one 'or' condition passes within its group.
        """
        # Group conditions by 'or_group' key
        grouped_conditions = {}
        for condition in self.conditions:
            group = condition.get('or_group', 'default_and_group')
            if group not in grouped_conditions:
                grouped_conditions[group] = []
            grouped_conditions[group].append(condition)

        for group, conditions_in_group in grouped_conditions.items():
            if group == 'default_and_group': # These are conditions that must ALL be true
                for condition in conditions_in_group:
                    if not self._check_condition(fact_base, condition):
                        return False
            else: # These are 'or' groups, at least one condition in the group must be true
                group_passed = False
                for condition in conditions_in_group:
                    if self._check_condition(fact_base, condition):
                        group_passed = True
                        break
                if not group_passed:
                    return False # If no condition in an 'or' group passed, the rule fails

        return True # All conditions (and/or groups) passed

    def _check_condition(self, fact_base: FactBase, condition: dict):
        """Helper to check a single condition."""
        fact_key = condition['fact']
        operator = condition['op']
        expected_value = condition['value']
        
        current_value = fact_base.get_fact(fact_key)

        if operator == '==':
            return current_value == expected_value
        elif operator == '!=':
            return current_value != expected_value
        elif operator == 'in': 
            # For 'in' operator, current_value should be a list, and expected_value an item
            return isinstance(current_value, list) and expected_value in current_value
        elif operator == 'contains':
            # For 'contains', expected_value should be a substring/item in current_value (string or list)
            if isinstance(current_value, list):
                return expected_value in current_value
            elif isinstance(current_value, str):
                return expected_value in current_value
            return False
        elif operator == 'not_contains':
            # For 'not_contains', expected_value should NOT be a substring/item in current_value
            if isinstance(current_value, list):
                return expected_value not in current_value
            elif isinstance(current_value, str):
                return expected_value not in current_value
            return True # If current_value is not list/str, and expected_value is not None, implicitly true (doesn't contain)
        elif operator == 'exists':
            return current_value is not None
        elif operator == 'not_exists':
            return current_value is None
        elif operator == 'is_not_empty':
            return current_value is not None and len(current_value) > 0
        elif operator == 'contains_any_of':
            # Checks if the fact_list contains at least one item from the expected_value list
            if not isinstance(current_value, list) or not isinstance(expected_value, list):
                return False
            return any(item in current_value for item in expected_value)
        elif operator == 'does_not_contain_all':
            # Checks if the fact_list does NOT contain all items from the expected_value list
            if not isinstance(current_value, list) or not isinstance(expected_value, list):
                return False # If not lists, can't check 'contains all'
            return not all(item in current_value for item in expected_value)
        else:
            print(f"Warning: Unknown operator '{operator}' for fact '{fact_key}'. Condition evaluation might fail.")
            return False

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
        self.consolidated_output_file = "consolidated_nmap_results.json"
        self.consolidated_nmap_data = [] 
        if os.path.exists(consolidated_output_file) and os.path.getsize(consolidated_output_file) > 0:
            try:
                with open(consolidated_output_file, 'r') as f:
                    self.consolidated_nmap_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Existing consolidated file '{consolidated_output_file}' is not valid JSON. Starting fresh.")
                self.consolidated_nmap_data = []
    def _deep_merge_nmap_host_data(self, existing_host, new_host):
        """
        Recursively merges new_host data into existing_host.
        Prioritizes new data for single values, merges lists/dictionaries.
        This is a more generic deep merge for Nmap JSON structure.
        """
        for key, new_value in new_host.items():
            if key not in existing_host:
                existing_host[key] = new_value
            else:
                existing_value = existing_host[key]
                if isinstance(new_value, dict) and isinstance(existing_value, dict):
                    self._deep_merge_nmap_host_data(existing_value, new_value)
                elif isinstance(new_value, list) and isinstance(existing_value, list):
                    # Special handling for Nmap lists that should be unique or merged by ID
                    if key in ['protocols', 'hostscript']:
                        # For 'protocols', each item in the list is a dict for a port/proto
                        # For 'hostscript', each item is a dict for a script result
                        # We need to merge by a unique identifier (port for protocols, id for hostscript)
                        existing_ids = {item.get('port') if key == 'protocols' else item.get('id'): item for item in existing_value}
                        for new_item in new_value:
                            item_id = new_item.get('port') if key == 'protocols' else new_item.get('id')
                            if item_id and item_id in existing_ids:
                                self._deep_merge_nmap_host_data(existing_ids[item_id], new_item)
                            else:
                                existing_value.append(new_item)
                    else:
                        # For other lists (like 'addresses', 'status'), simply extend and unique if necessary
                        # Nmap's JSON structure often has simple lists that can just be extended.
                        existing_host[key] = list(set(existing_value + new_value)) # Basic unique merge for simple lists
                else:
                    # For non-list/dict types, new value overwrites existing
                    existing_host[key] = new_value
    def run(self):
        """
        Runs the inference process.
        """
        print("--- Starting Nmap Decision Inference ---")
        
        max_passes = 10 # Increased max passes to allow more rule firing
        for i in range(max_passes):
            rules_fired_in_pass = 0
            print(f"\n--- Inference Pass {i+1} (Current Stage: {self.fact_base.get_fact('scan_stage', 'unknown')})---")
            
            current_decisions_for_pass = []
            
            # Create a copy of rules to iterate over, in case new rules are added or priorities change dynamically (not in this version)
            # Or, just iterate over self.rules directly if rules are static after initialization
            for rule in self.rules:
                # Check if the rule has already been fired and if it's not a rule designed to fire multiple times (e.g., initial scans)
                # For simplicity, all rules currently fire once. If a rule should re-evaluate, remove from self.fired_rules
                if rule.rule_id not in self.fired_rules and rule.evaluate(self.fact_base):
                    print(f"Rule Fired: {rule.rule_id} - {rule.description}")
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

                    # Dynamic fact replacement in Nmap command
                    # This block can be extended for other dynamic facts, e.g., {fact:target_os}
                    if "{fact:open_tcp_ports}" in final_nmap_command:
                        open_ports = self.fact_base.get_fact('open_tcp_ports', [])
                        if open_ports:
                            formatted_ports = ",".join(map(str, open_ports))
                            final_nmap_command = final_nmap_command.replace("{fact:open_tcp_ports}", formatted_ports)
                        else:
                            print(f"[WARNING] Rule {decision['rule_id']}: Nmap command requires open_tcp_ports, but none found. Skipping command.")
                            continue # Skip this Nmap command if ports are missing

                    if "{fact:open_http_ports}" in final_nmap_command:
                        open_http_ports = self.fact_base.get_fact('open_http_ports', [])
                        if open_http_ports:
                            formatted_ports = ",".join(map(str, open_http_ports))
                            final_nmap_command = final_nmap_command.replace("{fact:open_http_ports}", formatted_ports)
                        else:
                            print(f"[WARNING] Rule {decision['rule_id']}: Nmap command requires open_http_ports, but none found. Skipping command.")
                            continue # Skip this Nmap command if ports are missing
                    
                    if "{fact:open_udp_ports}" in final_nmap_command:
                        open_udp_ports = self.fact_base.get_fact('open_udp_ports', [])
                        if open_udp_ports:
                            formatted_ports = ",".join(map(str, open_udp_ports))
                            final_nmap_command = final_nmap_command.replace("{fact:open_udp_ports}", formatted_ports)
                        else:
                            print(f"[WARNING] Rule {decision['rule_id']}: Nmap command requires open_udp_ports, but none found. Skipping command.")
                            continue # Skip this Nmap command if ports are missing

                    print(f"\n[Executing Command from {decision['rule_id']}]: {final_nmap_command}")
                    
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
                            time.sleep(0.5) 

                            if not os.path.exists(temp_output_file) or os.path.getsize(temp_output_file) == 0:
                                print(f"Warning: Temporary Nmap JSON file '{temp_output_file}' not found or empty. Cannot parse.")
                                continue 

                            with open(temp_output_file, 'r') as f:
                                new_nmap_data = json.load(f)
                            print(f"Parsing new scan data from {temp_output_file}...")

                            # Merge new Nmap data into the consolidated list
                            # For Nmap, usually each new scan adds more detail or re-scans.
                            # A simple append of host entries is okay for now, but a more robust merge
                            # would update existing host entries with new port/script details.
                            if isinstance(new_nmap_data, list):
                                for host_entry in new_nmap_data:
                                    found_existing_host = False
                                    for existing_host in self.consolidated_nmap_data:
                                        if existing_host.get('host') == host_entry.get('host'):
                                            # Found existing host, merge relevant parts (ports, scripts, OS)
                                            # This is a simplified merge. A real-world scenario might need deep merging.

                                            # Merge protocols/ports
                                            for proto, ports in host_entry.get('protocols', {}).items():
                                                if proto not in existing_host.get('protocols', {}):
                                                    existing_host.setdefault('protocols', {})[proto] = []

                                                for new_port_entry in ports:
                                                    port_exists = False
                                                    for existing_port_entry in existing_host['protocols'][proto]:
                                                        if existing_port_entry.get('port') == new_port_entry.get('port'):
                                                            # Update existing port details
                                                            existing_port_entry.update(new_port_entry) # <--- Key update here
                                                            port_exists = True
                                                            break
                                                    if not port_exists:
                                                        existing_host['protocols'][proto].append(new_port_entry)

                                            # Merge hostscript results
                                            if 'hostscript' in host_entry:
                                                if 'hostscript' not in existing_host:
                                                    existing_host['hostscript'] = []
                                                for new_script_result in host_entry['hostscript']:
                                                    script_exists = False
                                                    for existing_script_result in existing_host['hostscript']:
                                                        if existing_script_result.get('id') == new_script_result.get('id'):
                                                            existing_script_result.update(new_script_result) # <--- Key update here
                                                            script_exists = True
                                                            break
                                                    if not script_exists:
                                                        existing_host['hostscript'].append(new_script_result)

                                            # Merge OS detection
                                            if 'os' in host_entry and not existing_host.get('os'):
                                                existing_host['os'] = host_entry['os']

                                            found_existing_host = True
                                            break

                                    if not found_existing_host:
                                        self.consolidated_nmap_data.append(host_entry)
                        except Exception as parse_e:
                            print(f"Error parsing temporary Nmap JSON output {temp_output_file}: {parse_e}")
                        finally:
                            if os.path.exists(temp_output_file):
                                os.remove(temp_output_file)
                                print(f"Cleaned up temporary file: {temp_output_file}")
                    else:
                        print(f"Nmap command exited with code {process.returncode}. Check output above for details.")

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
    It now also parses UDP ports if available.
    """
    facts = FactBase()
    
    if not isinstance(json_report_data, list) or not json_report_data:
        return facts

    if len(json_report_data) == 0:
        return facts

    host_data = json_report_data[0] # Assuming one host per single Nmap JSON output for simplicity

    host_ip = host_data.get('host')
    hostname = host_data.get('hostname')
    host_state = host_data.get('state')

    if host_ip:
        facts.add_fact('target_ip', host_ip)
    if hostname:
        facts.add_fact('target_hostname', hostname)
    if host_state:
        facts.add_fact('host_status', host_state)

    open_tcp_ports_list = []
    open_udp_ports_list = []
    open_http_ports_list = [] # To specifically track HTTP/HTTPS ports

    if 'protocols' in host_data:
        # Parse TCP ports
        if 'tcp' in host_data['protocols']:
            for port_entry in host_data['protocols']['tcp']:
                port = port_entry.get('port')
                state = port_entry.get('state')
                service = port_entry.get('service')
                version = port_entry.get('version')

                if state == 'open':
                    open_tcp_ports_list.append(port)
                    facts.add_fact(f'port_{port}_state', 'open')
                    if service:
                        facts.add_fact(f'port_{port}_service', service)
                        # Identify HTTP/HTTPS services
                        if service in ['http', 'https', 'http-proxy', 'ssl/http', 'http-alt']:
                            open_http_ports_list.append(port)
                    if version:
                        facts.add_fact(f'port_{port}_version', version)
                elif state in ['closed', 'filtered']:
                    facts.add_fact(f'port_{port}_state', state)
        
        # Parse UDP ports
        if 'udp' in host_data['protocols']:
            for port_entry in host_data['protocols']['udp']:
                port = port_entry.get('port')
                state = port_entry.get('state')
                service = port_entry.get('service')
                version = port_entry.get('version')

                if state == 'open':
                    open_udp_ports_list.append(port)
                    facts.add_fact(f'udp_port_{port}_state', 'open') # Differentiate UDP facts
                    if service:
                        facts.add_fact(f'udp_port_{port}_service', service)
                    if version:
                        facts.add_fact(f'udp_port_{port}_version', version)
                elif state in ['closed', 'filtered']:
                    facts.add_fact(f'udp_port_{port}_state', state)
                
    facts.add_fact('open_tcp_ports', sorted(list(set(open_tcp_ports_list))))
    facts.add_fact('open_udp_ports', sorted(list(set(open_udp_ports_list))))
    facts.add_fact('open_http_ports', sorted(list(set(open_http_ports_list)))) # Add the HTTP specific fact

    if 'os' in host_data and len(host_data['os']) > 0:
        facts.add_fact('target_os', host_data['os'][0]['name'])
    if 'hostscript' in host_data and len(host_data['hostscript']) > 0:
        facts.add_fact('initial_scripts_run', True)
        for script_result in host_data['hostscript']:
            script_id = script_result.get('id')
            script_output = script_result.get('output')
            if script_id and script_output:
                facts.add_fact(f'script_output_{script_id}', script_output)
                # Specific facts based on script output (for R505)
                if script_id == 'smb-vuln-ms17-010' and 'VULNERABLE' in script_output:
                    facts.add_fact('smb_vuln_ms17_010_detected', True)
                if script_id == 'ssl-heartbleed' and 'VULNERABLE' in script_output: # Example for heartbleed
                    facts.add_fact('ssl_heartbleed_detected', True)
                if script_id == 'ftp-anon' and 'Anonymous FTP login allowed' in script_output:
                    facts.add_fact('ftp_anon_allowed', True)


    scaninfo = host_data.get('scaninfo', {})
    if 'type' in scaninfo and 'services' in scaninfo:
        facts.add_fact('initial_scan_type', f"{scaninfo['type']}_{scaninfo['services']}")

    return facts

# --- Define the Rules (Updated with new operators and fact names) ---
def define_nmap_rules(target_ip):
    rules = []

    # Initial Scan & Host Status Rules (High Priority)
    rules.append(Rule(
        rule_id="R000_INITIAL_SCAN_REQUIRED",
        description="Trigger initial comprehensive Nmap scan if no scan data exists.",
        conditions=[
            {'fact': 'target_ip', 'op': 'not_exists', 'value': None}, # This condition needs to be inverted if SUBSCAN.py handles initial.
            {'fact': 'scan_stage', 'op': 'not_exists', 'value': None} # This condition means scan_stage is not set.
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

    # Optimization Rule (High Priority, to refine initial discovery)
    rules.append(Rule(
        rule_id="R200_TARGETED_PORT_SCAN",
        description="If scan_stage is 'initial_discovery_complete' and some open ports were found, but not all common ones, perform a more targeted scan on unlisted common ports.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'initial_discovery_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'is_not_empty', 'value': None}, # Ensure some ports are open
            {'fact': 'targeted_port_scan_done', 'op': 'not_exists', 'value': None},
            {'fact': 'open_tcp_ports', 'op': 'does_not_contain_all', 'value': [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]}
        ],
        actions=[
            {'type': 'log', 'message': f"Performing targeted scan on {target_ip} for specific common ports not yet discovered."},
            {'type': 'nmap_command', 'command': f"nmap -p 21,22,23,25,53,80,110,139,443,445,3389,8080 --reason {target_ip}"},
            {'type': 'add_fact', 'key': 'targeted_port_scan_done', 'value': True}
        ],
        priority=88,
        relevant_ports=[21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]
    ))

    # General Service/Vulnerability Scans (Transitioning from Initial to Detailed)
    rules.append(Rule(
        rule_id="R300_SERVICE_VERSIONING_SUPPLEMENTAL",
        description="Run comprehensive service version detection if not fully done by initial scan.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'initial_discovery_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'is_not_empty', 'value': None},
            {'fact': 'full_service_scan_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -sV -p {{fact:open_tcp_ports}} {target_ip}"},
            {'type': 'add_fact', 'key': 'full_service_scan_done', 'value': True},
            {'type': 'update_scan_stage', 'value': 'detailed_service_analysis'}
        ],
        priority=70,
        relevant_ports="All Open TCP Ports" 
    ))

    rules.append(Rule(
        rule_id="R400_GENERAL_VULN_SCRIPTS_SUPPLEMENTAL",
        description="Run general vulnerability scripts if not covered by initial scan.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'detailed_service_analysis'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'is_not_empty', 'value': None},
            {'fact': 'general_vuln_scripts_run', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap --script 'vuln' -p {{fact:open_tcp_ports}} {target_ip}"},
            {'type': 'add_fact', 'key': 'general_vuln_scripts_run', 'value': True},
            {'type': 'update_scan_stage', 'value': 'vulnerability_identification_complete'}
        ],
        priority=68, # Slightly lower priority than R300 to ensure versioning happens first
        relevant_ports="All Open TCP Ports" 
    ))

    # Deeper Service-Specific Enumeration (Post-R300/R400)

    rules.append(Rule(
        rule_id="R112_FTP_ENUMERATION",
        description="Enumerate FTP service for anonymous login, writable directories, and common vulnerabilities.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 21},
            {'fact': 'port_21_service', 'op': 'contains', 'value': 'ftp'},
            {'fact': 'ftp_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 21 --script ftp-anon,ftp-brute,ftp-enum,ftp-vsftpd-backdoor,ftp-proftpd-backdoor {target_ip}"},
            {'type': 'add_fact', 'key': 'ftp_enum_done', 'value': True}
        ],
        priority=67, # Adjusted priority
        relevant_ports=[21]
    ))

    rules.append(Rule(
        rule_id="R104_SSH_ENUMERATION",
        description="Enumerate SSH service for supported authentication methods and versions, and identify potential vulnerabilities.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 22},
            {'fact': 'port_22_service', 'op': 'contains', 'value': 'ssh'},
            {'fact': 'ssh_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 22 --script ssh-auth-methods,ssh-hostkey,ssh-brute,ssh-publickey-accept {target_ip}"},
            {'type': 'add_fact', 'key': 'ssh_enum_done', 'value': True}
        ],
        priority=66, 
        relevant_ports=[22]
    ))

    rules.append(Rule(
        rule_id="R105_SMTP_ENUMERATION",
        description="Enumerate SMTP service for user enumeration, open relays, and VRFY/EXPN command support.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            # Use 'contains_any_of' for multiple ports
            {'fact': 'open_tcp_ports', 'op': 'contains_any_of', 'value': [25, 465, 587]}, 
            # Use an 'or_group' for service checks on multiple ports
            {'fact': 'port_25_service', 'op': 'contains', 'value': 'smtp', 'or_group': 'smtp_service_check'}, 
            {'fact': 'port_465_service', 'op': 'contains', 'value': 'smtp', 'or_group': 'smtp_service_check'},
            {'fact': 'port_587_service', 'op': 'contains', 'value': 'smtp', 'or_group': 'smtp_service_check'},
            {'fact': 'smtp_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 25,465,587 --script smtp-commands,smtp-enum-users,smtp-open-relay,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720 {target_ip}"},
            {'type': 'add_fact', 'key': 'smtp_enum_done', 'value': True}
        ],
        priority=64,
        relevant_ports=[25, 465, 587]
    ))

    rules.append(Rule(
        rule_id="R106_MYSQL_ENUMERATION",
        description="Enumerate MySQL service for common vulnerabilities and information disclosure.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains', 'value': 3306},
            {'fact': 'port_3306_service', 'op': 'contains', 'value': 'mysql'},
            {'fact': 'mysql_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 3306 --script mysql-enum,mysql-info,mysql-vuln-cve2012-2122,mysql-brute {target_ip}"},
            {'type': 'add_fact', 'key': 'mysql_enum_done', 'value': True}
        ],
        priority=63,
        relevant_ports=[3306]
    ))

    rules.append(Rule(
        rule_id="R113_SMB_ENUMERATION", 
        description="Enumerate SMB service for shares, users, and common vulnerabilities like MS17-010.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains_any_of', 'value': [139, 445]}, 
            {'fact': 'port_139_service', 'op': 'contains', 'value': 'netbios-ssn', 'or_group': 'smb_service_check'},
            {'fact': 'port_445_service', 'op': 'contains', 'value': 'microsoft-ds', 'or_group': 'smb_service_check'},
            {'fact': 'smb_enum_done', 'op': 'not_exists', 'value': None} 
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p 139,445 --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-ms17-010 {target_ip}"},
            {'type': 'add_fact', 'key': 'smb_enum_done', 'value': True}
        ],
        priority=72, 
        relevant_ports=[139, 445]
    ))

    # Advanced Web Application Checks (Post-R101 HTTP Enumeration)
    rules.append(Rule(
        rule_id="R101_HTTP_ENUMERATION",
        description="Run common web enumeration scripts for open HTTP/HTTPS ports.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains_any_of', 'value': [80, 443, 8080, 8443]},
            {'fact': 'http_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p {{fact:open_http_ports}} --script http-enum,http-title,http-headers,http-server-header {target_ip}"},
            {'type': 'add_fact', 'key': 'http_enum_done', 'value': True}
        ],
        priority=65,
        relevant_ports=[80, 443, 8080, 8443]
    ))

    rules.append(Rule(
        rule_id="R107_WEBDAV_ENUMERATION",
        description="Check for WebDAV enabled and enumerate directories and allowed methods.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_http_ports', 'op': 'is_not_empty', 'value': None}, 
            {'fact': 'http_enum_done', 'op': '==', 'value': True},
            {'fact': 'webdav_check_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p {{fact:open_http_ports}} --script http-webdav-scan,http-methods {target_ip}"},
            {'type': 'add_fact', 'key': 'webdav_check_done', 'value': True}
        ],
        priority=60,
        relevant_ports=[80, 443, 8080, 8443]
    ))

    rules.append(Rule(
        rule_id="R108_HTTP_LOGIN_PAGE_DETECTION",
        description="Detect common login pages to inform potential brute-force attempts and identify authentication mechanisms.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_http_ports', 'op': 'is_not_empty', 'value': None},
            {'fact': 'http_enum_done', 'op': '==', 'value': True},
            {'fact': 'http_login_check_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p {{fact:open_http_ports}} --script http-form-brute,http-auth-finder,http-login {target_ip}"},
            {'type': 'add_fact', 'key': 'http_login_check_done', 'value': True}
        ],
        priority=58,
        relevant_ports=[80, 443, 8080, 8443]
    ))

    rules.append(Rule(
        rule_id="R109_HTTP_DIR_BRUTE",
        description="Perform extensive directory and file enumeration for common paths, and scan for common web vulnerabilities.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_http_ports', 'op': 'is_not_empty', 'value': None},
            {'fact': 'http_enum_done', 'op': '==', 'value': True},
            {'fact': 'http_dir_brute_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -p {{fact:open_http_ports}} --script http-enum,http-robots.txt,http-sitemap-generator,http-vuln-cve2014-8877,http-shellshock {target_ip}"},
            {'type': 'add_fact', 'key': 'http_dir_brute_done', 'value': True}
        ],
        priority=55,
        relevant_ports=[80, 443, 8080, 8443]
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

    # General Vulnerability Checks
    rules.append(Rule(
        rule_id="R110_DNS_ENUMERATION",
        description="Check for DNS server vulnerabilities like zone transfer and cache snooping.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_udp_ports', 'op': 'contains', 'value': 53}, 
            {'fact': 'udp_port_53_service', 'op': 'contains', 'value': 'domain'}, # Changed to udp_port_53_service
            {'fact': 'dns_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -sU -p 53 --script dns-enum,dns-zone-transfer,dns-recursion,dns-brute {target_ip}"},
            {'type': 'add_fact', 'key': 'dns_enum_done', 'value': True}
        ],
        priority=65,
        relevant_ports=[53]
    ))

    rules.append(Rule(
        rule_id="R111_SNMP_ENUMERATION",
        description="Attempt to enumerate SNMP public community strings and gather system information.",
        conditions=[
            {'fact': 'scan_stage', 'op': 'in', 'value': ['detailed_service_analysis', 'vulnerability_identification_complete']},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_udp_ports', 'op': 'contains', 'value': 161},
            {'fact': 'udp_port_161_service', 'op': 'contains', 'value': 'snmp'}, # Changed to udp_port_161_service
            {'fact': 'snmp_enum_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'nmap_command', 'command': f"nmap -sU -p 161 --script snmp-brute,snmp-info,snmp-interfaces,snmp-sysdescr {target_ip}"},
            {'type': 'add_fact', 'key': 'snmp_enum_done', 'value': True}
        ],
        priority=62,
        relevant_ports=[161]
    ))


    # Post-Scan Analysis and Suggestions (Lower Priority)
    rules.append(Rule(
        rule_id="R500_EXPLOIT_METASPLOIT_FTP_ANON",
        description="Suggest Metasploit for anonymous FTP login if found.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'port_21_state', 'op': '==', 'value': 'open'},
            {'fact': 'port_21_service', 'op': 'contains', 'value': 'ftp'},
            {'fact': 'ftp_anon_allowed', 'op': '==', 'value': True} # Changed to specific fact
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
            {'fact': 'smb_vuln_ms17_010_detected', 'op': '==', 'value': True} # Changed to specific fact
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
            {'fact': 'open_http_ports', 'op': 'is_not_empty', 'value': None}, 
            {'fact': 'http_enum_done', 'op': '==', 'value': True}, # Ensure enum was done to have script output
            {'fact': 'script_output_http-enum', 'op': 'exists', 'value': None} # More general check
        ],
        actions=[
            {'type': 'log', 'message': f"[EXPLOIT SUGGESTION] Web server on {target_ip}:80/443 likely has vulnerabilities. Consider using Burp Suite, OWASP ZAP, or specific web exploit frameworks."}
        ],
        priority=20,
        relevant_ports=[80,443]
    ))
    
    rules.append(Rule(
        rule_id="R503_EXPLOIT_BRUTE_FORCE_GENERIC",
        description="Suggest brute-forcing if common login services (SSH, FTP, HTTP, Telnet, SMB) are found.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_tcp_ports', 'op': 'contains_any_of', 'value': [21, 22, 23, 80, 443, 139, 445]}, 
            {'fact': 'brute_force_suggestion_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'log', 'message': f"[EXPLOIT SUGGESTION] Common login services detected on {target_ip}. Consider credential brute-forcing using tools like Hydra, Medusa, or CrackMapExec (for SMB)."},
            {'type': 'add_fact', 'key': 'brute_force_suggestion_done', 'value': True}
        ],
        priority=15,
        relevant_ports=[21, 22, 23, 80, 443, 139, 445]
    ))

    rules.append(Rule(
        rule_id="R504_EXPLOIT_MANUAL_WEB_REVIEW",
        description="If web services are present, suggest deeper manual review and specialized web application scanning.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            {'fact': 'open_http_ports', 'op': 'is_not_empty', 'value': None},
            {'fact': 'manual_web_review_suggestion_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'log', 'message': f"[EXPLOIT SUGGESTION] Active web services on {target_ip}. Perform manual web application penetration testing using tools like Burp Suite or ZAP for vulnerabilities like SQLi, XSS, insecure direct object references, deserialization flaws, etc."},
            {'type': 'add_fact', 'key': 'manual_web_review_suggestion_done', 'value': True}
        ],
        priority=12,
        relevant_ports=[80, 443, 8080, 8443]
    ))

    rules.append(Rule(
        rule_id="R505_VULN_PATCHING_SUGGESTION",
        description="If specific high-impact vulnerabilities (e.g., MS17-010, Heartbleed) are identified, suggest patching.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'host_status', 'op': '==', 'value': 'up'},
            # Use an 'or_group' for these specific high-impact vulnerabilities
            {'fact': 'smb_vuln_ms17_010_detected', 'op': '==', 'value': True, 'or_group': 'high_impact_vuln_check'},
            {'fact': 'ssl_heartbleed_detected', 'op': '==', 'value': True, 'or_group': 'high_impact_vuln_check'},
            {'fact': 'patching_suggestion_done', 'op': 'not_exists', 'value': None}
        ],
        actions=[
            {'type': 'log', 'message': f"[VULNERABILITY REMEDIATION] Critical vulnerabilities detected on {target_ip}. Prioritize applying security patches and updates for affected services."},
            {'type': 'add_fact', 'key': 'patching_suggestion_done', 'value': True}
        ],
        priority=18,
        relevant_ports="N/A"
    ))

    # Final Scan Phase Rule
    rules.append(Rule(
        rule_id="R900_SCAN_PHASE_COMPLETE",
        description="Indicate that the active scanning phase is considered complete.",
        conditions=[
            {'fact': 'scan_stage', 'op': '==', 'value': 'vulnerability_identification_complete'},
            {'fact': 'full_service_scan_done', 'op': '==', 'value': True},
            {'fact': 'general_vuln_scripts_run', 'op': '==', 'value': True},
            {'fact': 'ftp_enum_done', 'op': 'exists', 'value': None}, 
            {'fact': 'http_enum_done', 'op': 'exists', 'value': None},
            {'fact': 'ssl_tls_check_done', 'op': 'exists', 'value': None},
            {'fact': 'smb_enum_done', 'op': 'exists', 'value': None},
            {'fact': 'ssh_enum_done', 'op': 'exists', 'value': None}, 
            {'fact': 'smtp_enum_done', 'op': 'exists', 'value': None}, 
            {'fact': 'mysql_enum_done', 'op': 'exists', 'value': None}, 
            {'fact': 'webdav_check_done', 'op': 'exists', 'value': None}, 
            {'fact': 'http_login_check_done', 'op': 'exists', 'value': None}, 
            {'fact': 'http_dir_brute_done', 'op': 'exists', 'value': None}, 
            {'fact': 'dns_enum_done', 'op': 'exists', 'value': None}, 
            {'fact': 'snmp_enum_done', 'op': 'exists', 'value': None}, 
            # Make targeted_port_scan_done truly optional by making its condition `True` if it doesn't exist,
            # or `== True` if it does. The 'optional': True field in the condition dictionary is just a marker,
            # not directly used by the evaluation logic.
            {'fact': 'targeted_port_scan_done', 'op': 'exists', 'value': None, 'optional': True, 'or_group': 'optional_scan_complete_check'},
            {'fact': 'targeted_port_scan_done', 'op': '==', 'value': True, 'or_group': 'optional_scan_complete_check'},
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
            # Note: Ensure SUBSCAN.py is designed to take IP as input and output to scanout.json
            process = subprocess.run(
                ["python3", "SUBSCAN.py"],
                input=f"{initial_target_ip}\n", # Pass target_ip via stdin
                capture_output=True,
                text=True,
                check=False
            )
            print(f"\nSUBSCAN.py stdout:\n{process.stdout}")
            if process.stderr:
                print(f"SUBSCAN.py stderr:\n{process.stderr}")

            if process.returncode != 0:
                print(f"Warning: SUBSCAN.py exited with code {process.returncode}. Please check its output for errors.")
            
            time.sleep(1) # Give system a moment to write the file

            if not os.path.exists(initial_scan_file_path) or os.path.getsize(initial_scan_file_path) == 0:
                print(f"Error: SUBSCAN.py failed to create a valid '{initial_scan_file_path}'. Exiting.")
                sys.exit(1)
            else:
                print(f"Initial scan data successfully generated in '{initial_scan_file_path}'.")
        except FileNotFoundError:
            print("Error: SUBSCAN.py not found. Make sure it's in the same directory and executable.")
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
    
    # If target_ip wasn't in scanout.json but was provided by user for SUBSCAN.py
    if not initial_facts.get_fact('target_ip') and initial_target_ip:
        initial_facts.add_fact('target_ip', initial_target_ip)

    target_ip = initial_facts.get_fact('target_ip')
    if not target_ip:
        print("Error: Could not determine target IP from the report. Exiting.")
        sys.exit(1)
    
    # Set initial scan stage if not already set by parsing
    if not initial_facts.get_fact('scan_stage'):
        initial_facts.add_fact('scan_stage', 'initial_discovery_complete')

    print("\nInitial Facts for {}:".format(target_ip))
    print(initial_facts)

    # Initialize the consolidated_nmap_results.json with the initial scan data
    try:
        with open(consolidated_output_file_path, 'w') as f:
            json.dump(nmap_report_data, f, indent=2)
        print(f"Initial scan data written to consolidated file: {consolidated_output_file_path}")
    except Exception as e:
        print(f"Error writing initial scan data to consolidated file: {e}")


    # --- Step 3: Initialize and run the Inference Engine ---
    rules = define_nmap_rules(target_ip)
    engine = InferenceEngine(initial_facts, rules, consolidated_output_file_path)
    engine.run()