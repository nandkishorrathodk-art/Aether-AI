"""
Bug Bounty CLI Tool
Interactive command-line interface for bug bounty hunting
"""

import requests
import json
import sys
from typing import Optional

API_URL = "http://127.0.0.1:8000"


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   AETHER AI - BUG BOUNTY HUNTER CLI                     ║
║   Automated Penetration Testing with AI                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
""")


def print_menu():
    print("\n" + "="*60)
    print("  MAIN MENU")
    print("="*60)
    print("\n  1. Add Target")
    print("  2. Run Reconnaissance")
    print("  3. Scan Target")
    print("  4. Analyze Vulnerability")
    print("  5. Generate Payloads")
    print("  6. View Targets")
    print("  7. View Findings")
    print("  8. BurpSuite Status")
    print("  9. Full Automation")
    print("  0. Exit")
    print("\n" + "="*60)


def add_target():
    """Add bug bounty target"""
    print("\n" + "="*60)
    print("  ADD BUG BOUNTY TARGET")
    print("="*60 + "\n")
    
    domain = input("  Domain (e.g., example.com): ").strip()
    
    scope = []
    print("\n  Enter scope URLs (one per line, empty line to finish):")
    while True:
        url = input("  > ").strip()
        if not url:
            break
        scope.append(url)
    
    if not scope:
        print("\n  ✗ No scope URLs provided")
        return
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/security/bugbounty/target",
            json={
                "domain": domain,
                "scope": scope,
                "out_of_scope": [],
                "program_type": "web"
            }
        )
        
        if response.status_code == 200:
            print(f"\n  ✓ Target '{domain}' added successfully")
            print(f"  Scope URLs: {len(scope)}")
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
            print(f"  {response.text}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def run_recon():
    """Run reconnaissance"""
    print("\n" + "="*60)
    print("  RECONNAISSANCE")
    print("="*60 + "\n")
    
    domain = input("  Target domain: ").strip()
    
    if not domain:
        print("\n  ✗ Domain required")
        return
    
    print(f"\n  Running reconnaissance on {domain}...")
    print("  This may take a few minutes...")
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/security/bugbounty/recon?domain={domain}",
            timeout=300
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print("\n  ✓ Reconnaissance Complete")
            print(f"\n  Subdomains Found: {len(data.get('subdomains', []))}")
            
            subdomains = data.get('subdomains', [])[:10]
            for sub in subdomains:
                print(f"    - {sub}")
            
            if len(data.get('subdomains', [])) > 10:
                print(f"    ... and {len(data.get('subdomains', [])) - 10} more")
            
            print(f"\n  Technologies Detected: {len(data.get('technologies', []))}")
            for tech in data.get('technologies', []):
                print(f"    - {tech}")
            
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def scan_target():
    """Scan target"""
    print("\n" + "="*60)
    print("  VULNERABILITY SCAN")
    print("="*60 + "\n")
    
    domain = input("  Target domain: ").strip()
    deep_scan = input("  Deep scan? (y/n) [y]: ").strip().lower() != 'n'
    
    if not domain:
        print("\n  ✗ Domain required")
        return
    
    print(f"\n  Scanning {domain}...")
    print("  This may take several minutes...")
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/security/bugbounty/scan?domain={domain}&deep_scan={deep_scan}",
            timeout=600
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print("\n  ✓ Scan Complete")
            print(f"\n  Total Vulnerabilities: {data.get('total_vulnerabilities', 0)}")
            print(f"  Critical: {data.get('critical', 0)}")
            print(f"  High: {data.get('high', 0)}")
            
            vulns = data.get('vulnerabilities', [])
            if vulns:
                print(f"\n  Top Findings:")
                for i, vuln in enumerate(vulns[:5], 1):
                    print(f"    {i}. {vuln.get('type')} - {vuln.get('severity')}")
                    print(f"       URL: {vuln.get('url')}")
                    print(f"       CVSS: {vuln.get('cvss_score', 'N/A')}")
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def analyze_vuln():
    """Analyze vulnerability"""
    print("\n" + "="*60)
    print("  AI VULNERABILITY ANALYSIS")
    print("="*60 + "\n")
    
    vuln_type = input("  Vulnerability Type (e.g., SQL Injection): ").strip()
    url = input("  Affected URL: ").strip()
    severity = input("  Severity (Critical/High/Medium/Low): ").strip()
    evidence = input("  Evidence/Proof: ").strip()
    
    if not all([vuln_type, url, severity]):
        print("\n  ✗ All fields required")
        return
    
    print("\n  Analyzing with AI...")
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/security/analyze/vulnerability",
            json={
                "vulnerability_data": {
                    "vulnerability_type": vuln_type,
                    "severity": severity,
                    "confidence": "Firm",
                    "url": url,
                    "evidence": evidence
                },
                "deep_analysis": True
            },
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            
            print("\n  ✓ Analysis Complete")
            print(f"\n  Type: {data.get('vulnerability_type')}")
            print(f"  Severity: {data.get('severity')}")
            print(f"  CVSS Score: {data.get('cvss_score')}")
            print(f"  CWE: {data.get('cwe_id')}")
            print(f"  OWASP: {data.get('owasp_category')}")
            
            print("\n  Exploitation Steps:")
            for i, step in enumerate(data.get('exploitation_steps', [])[:5], 1):
                print(f"    {i}. {step}")
            
            print(f"\n  Impact:")
            print(f"    {data.get('impact_analysis', '')[:200]}...")
            
            if data.get('ai_insights'):
                print(f"\n  AI Insights:")
                print(f"    {data['ai_insights'][:300]}...")
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def generate_payloads():
    """Generate payloads"""
    print("\n" + "="*60)
    print("  AI PAYLOAD GENERATION")
    print("="*60 + "\n")
    
    payload_type = input("  Payload type (XSS/SQLi/LFI/RCE/etc): ").strip()
    count = input("  Number of payloads [20]: ").strip()
    count = int(count) if count.isdigit() else 20
    
    if not payload_type:
        print("\n  ✗ Payload type required")
        return
    
    print(f"\n  Generating {count} {payload_type} payloads with AI...")
    
    try:
        response = requests.get(
            f"{API_URL}/api/v1/security/payloads/{payload_type}?count={count}",
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            payloads = data.get('payloads', [])
            
            print(f"\n  ✓ Generated {len(payloads)} payloads")
            print("\n  Payloads:")
            for i, payload in enumerate(payloads[:15], 1):
                print(f"    {i}. {payload}")
            
            if len(payloads) > 15:
                print(f"    ... and {len(payloads) - 15} more")
            
            save = input("\n  Save to file? (y/n): ").strip().lower() == 'y'
            if save:
                filename = f"{payload_type}_payloads.txt"
                with open(filename, 'w') as f:
                    f.write('\n'.join(payloads))
                print(f"\n  ✓ Saved to {filename}")
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def view_targets():
    """View all targets"""
    print("\n" + "="*60)
    print("  BUG BOUNTY TARGETS")
    print("="*60 + "\n")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/security/bugbounty/targets")
        
        if response.status_code == 200:
            data = response.json()
            targets = data.get('targets', [])
            
            if not targets:
                print("  No targets added yet")
            else:
                print(f"  Total Targets: {data.get('total_targets', 0)}\n")
                for i, target in enumerate(targets, 1):
                    print(f"  {i}. {target.get('domain')}")
                    print(f"     Scope: {len(target.get('scope', []))} URLs")
                    print(f"     Type: {target.get('program_type')}")
                    print()
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def view_findings():
    """View all findings"""
    print("\n" + "="*60)
    print("  VULNERABILITY FINDINGS")
    print("="*60 + "\n")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/security/bugbounty/findings")
        
        if response.status_code == 200:
            data = response.json()
            findings = data.get('findings', [])
            
            if not findings:
                print("  No findings yet")
            else:
                print(f"  Total Findings: {data.get('total_findings', 0)}")
                print(f"  Critical: {data.get('critical', 0)}")
                print(f"  High: {data.get('high', 0)}")
                print(f"  Medium: {data.get('medium', 0)}")
                print(f"  Low: {data.get('low', 0)}\n")
                
                for i, finding in enumerate(findings[:10], 1):
                    print(f"  {i}. {finding.get('type')} - {finding.get('severity')}")
                    print(f"     URL: {finding.get('url')}")
                    print(f"     CVSS: {finding.get('cvss_score', 'N/A')}")
                    print()
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def burp_status():
    """Check BurpSuite status"""
    print("\n" + "="*60)
    print("  BURPSUITE STATUS")
    print("="*60 + "\n")
    
    try:
        response = requests.get(f"{API_URL}/api/v1/security/burp/status")
        data = response.json()
        
        status = data.get('status', 'unknown')
        
        if status == "running":
            print("  ✓ BurpSuite: CONNECTED")
            print(f"  Version: {data.get('version', 'N/A')}")
        else:
            print(f"  ✗ BurpSuite: {status.upper()}")
            if status == "offline":
                print("\n  To enable BurpSuite features:")
                print("  1. Start BurpSuite Professional")
                print("  2. Enable REST API in Extensions")
                print("  3. Configure API key if required")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def full_automation():
    """Full automation"""
    print("\n" + "="*60)
    print("  FULL BUG BOUNTY AUTOMATION")
    print("="*60 + "\n")
    
    domain = input("  Target domain: ").strip()
    output_dir = input("  Output directory [./bug_bounty_results]: ").strip()
    
    if not domain:
        print("\n  ✗ Domain required")
        return
    
    if not output_dir:
        output_dir = "./bug_bounty_results"
    
    print(f"\n  Starting full automation for {domain}")
    print(f"  This will take a while (15-30 minutes)")
    print(f"  Results will be saved to: {output_dir}")
    print("\n  Running in background...")
    
    try:
        response = requests.post(
            f"{API_URL}/api/v1/security/bugbounty/automate",
            json={
                "domain": domain,
                "output_dir": output_dir
            },
            timeout=10
        )
        
        if response.status_code == 200:
            print("\n  ✓ Automation started!")
            print(f"  Check {output_dir} for results")
        else:
            print(f"\n  ✗ Failed: {response.status_code}")
    
    except Exception as e:
        print(f"\n  ✗ Error: {e}")


def main():
    """Main CLI loop"""
    print_banner()
    
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        if response.status_code != 200:
            print("\n  ✗ Error: API server not responding")
            print("  Please start the server first (run BUG-BOUNTY.bat)")
            sys.exit(1)
    except:
        print("\n  ✗ Error: Cannot connect to API server")
        print("  Please start the server first (run BUG-BOUNTY.bat)")
        sys.exit(1)
    
    print("\n  ✓ Connected to Aether AI Security Server")
    
    while True:
        print_menu()
        
        choice = input("\n  Select option: ").strip()
        
        if choice == "1":
            add_target()
        elif choice == "2":
            run_recon()
        elif choice == "3":
            scan_target()
        elif choice == "4":
            analyze_vuln()
        elif choice == "5":
            generate_payloads()
        elif choice == "6":
            view_targets()
        elif choice == "7":
            view_findings()
        elif choice == "8":
            burp_status()
        elif choice == "9":
            full_automation()
        elif choice == "0":
            print("\n  Goodbye! Happy hunting! 🎯\n")
            break
        else:
            print("\n  ✗ Invalid option")
        
        input("\n  Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Interrupted. Goodbye!\n")
        sys.exit(0)
