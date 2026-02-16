# Bug Bounty Automation with Aether AI

Complete guide for automated bug bounty hunting using Aether AI's BurpSuite integration and AI-powered vulnerability analysis.

## ⚠️ CRITICAL: Ethical Use Only

**WARNING**: This system is designed ONLY for:
- ✅ **Authorized bug bounty programs** (HackerOne, Bugcrowd, Intigriti, etc.)
- ✅ **Penetration testing with written authorization**
- ✅ **Personal projects you own**
- ✅ **Educational environments with permission**

**NEVER test targets without explicit authorization. Unauthorized testing is illegal.**

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Workflow](#workflow)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Features

### 🔍 Reconnaissance Engine
- **Passive Subdomain Enumeration**: Certificate Transparency logs, DNS records
- **Active Scanning**: Port scanning, technology detection
- **Asset Discovery**: URLs, endpoints, parameters
- **AI-Powered Analysis**: Attack surface recommendations

### 🛡️ BurpSuite Integration
- **Automated Scanning**: CrawlAndAudit, Deep Scan, Light Active
- **Real-time Monitoring**: Scan status and progress tracking
- **Issue Retrieval**: Automatic vulnerability extraction
- **Configurable Scans**: Custom crawl depth, audit checks

### 🧠 AI Vulnerability Analysis
- **Classification**: 18+ vulnerability types (SQLi, XSS, SSRF, RCE, etc.)
- **False Positive Filtering**: AI-powered accuracy improvement
- **CVSS Scoring**: Automatic severity calculation
- **Attack Vectors**: Intelligent exploit path suggestions

### 💥 Exploit Generation
- **Proof-of-Concept**: Safe, non-destructive payloads
- **Multiple Formats**: Python scripts, cURL commands, manual steps
- **WAF Bypass Techniques**: AI-generated evasion tactics
- **Chaining**: Multi-step exploitation paths

### 📝 Report Generation
- **Platform-Specific**: HackerOne, Bugcrowd, Intigriti templates
- **Multiple Formats**: Markdown, HTML, JSON
- **AI Enhancement**: Professional writing, impact analysis
- **Bounty Estimation**: Intelligent reward predictions

### ✅ Scope Validation
- **Safety First**: Automatic out-of-scope detection
- **Wildcard Matching**: Domain and subdomain validation
- **IP Range Support**: CIDR notation
- **Warnings**: Pre-scan scope verification

---

## Prerequisites

### Required Software

1. **BurpSuite Professional** (v2023.1+)
   - Download: https://portswigger.net/burp/pro
   - Enable REST API (User Options → Misc → REST API)
   - Note API URL (default: `http://localhost:1337`)
   - Optional: Generate API key for authentication

2. **Python 3.8+** (Already installed with Aether AI)

3. **Aether AI Backend** (Already running)

### Optional Tools

- **Subfinder**: Enhanced subdomain enumeration
- **Nmap**: Advanced port scanning (be careful with authorization!)
- **Nuclei**: Template-based vulnerability scanning

---

## Setup

### 1. Install BurpSuite Professional

```bash
# Download from PortSwigger website
# Install and launch BurpSuite
# Navigate to: User Options → Misc → REST API
# Enable "REST API service"
# Note the API URL (default: http://localhost:1337)
```

### 2. Configure Aether AI

**Option A: Via API (Recommended)**

```bash
# Start Aether AI backend
cd C:\Users\nandk\.zenflow\worktrees\nitro-v-f99b
start-aether.bat

# Configure BurpSuite connection
curl -X POST "http://localhost:8000/api/v1/bugbounty/configure" \
  -H "Content-Type: application/json" \
  -d '{
    "api_url": "http://localhost:1337",
    "api_key": null
  }'
```

**Option B: Via Python**

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/bugbounty/configure",
    json={
        "api_url": "http://localhost:1337",
        "api_key": None  # Optional
    }
)

print(response.json())
# Output: {"status": "configured", "burp_version": {...}}
```

### 3. Create Bug Bounty Program

```python
import requests

# Create program configuration
response = requests.post(
    "http://localhost:8000/api/v1/bugbounty/programs",
    json={
        "name": "Example Corp Bug Bounty",
        "platform": "HackerOne",
        "in_scope": [
            "*.example.com",
            "https://api.example.com/*",
            "https://admin.example.com/*"
        ],
        "out_of_scope": [
            "*.test.example.com",
            "https://status.example.com"
        ],
        "no_dos": True,
        "no_social_engineering": True
    }
)

print(response.json())
```

---

## Workflow

### Complete Bug Bounty Automation Flow

```
1. Configure Program Scope
   ↓
2. Reconnaissance (Passive → Active)
   ↓
3. Validate Scope
   ↓
4. BurpSuite Scanning
   ↓
5. AI Vulnerability Analysis
   ↓
6. Exploit Generation
   ↓
7. Report Creation
   ↓
8. Submission
```

### Step-by-Step Example

#### Step 1: Reconnaissance

```python
import requests
import time

# Start reconnaissance
recon_response = requests.post(
    "http://localhost:8000/api/v1/bugbounty/recon",
    json={
        "domain": "example.com",
        "program_name": "Example Corp Bug Bounty",
        "scope": ["*.example.com"],
        "passive_only": False
    }
)

target_id = recon_response.json()["target_id"]
print(f"Reconnaissance started: {target_id}")

# Wait for completion (runs in background)
time.sleep(60)

# Get results
results = requests.get(
    f"http://localhost:8000/api/v1/bugbounty/recon/{target_id}"
)

recon_data = results.json()
print(f"Found {recon_data['subdomains_count']} subdomains")
print(f"Technologies: {recon_data['technologies']}")
```

#### Step 2: Start Scan

```python
# Scan a discovered target
scan_response = requests.post(
    "http://localhost:8000/api/v1/bugbounty/scan",
    json={
        "target_url": "https://app.example.com",
        "scan_type": "CrawlAndAudit",
        "crawl_depth": 5,
        "check_scope": True
    }
)

scan_id = scan_response.json()["scan_id"]
print(f"Scan started: {scan_id}")
```

#### Step 3: Monitor Scan

```python
import time

while True:
    status = requests.get(
        f"http://localhost:8000/api/v1/bugbounty/scan/{scan_id}"
    ).json()
    
    print(f"Status: {status['scan_status']}")
    print(f"Progress: {status.get('scan_metrics', {}).get('crawl_requests_made', 0)}")
    
    if status['scan_status'] in ['succeeded', 'failed']:
        break
    
    time.sleep(30)  # Check every 30 seconds
```

#### Step 4: Analyze Vulnerabilities

```python
# Get scan issues
issues_response = requests.get(
    f"http://localhost:8000/api/v1/bugbounty/scan/{scan_id}/issues"
)

issues = issues_response.json()
print(f"Found {issues['issues_count']} vulnerabilities")

# AI analysis
analysis = requests.post(
    "http://localhost:8000/api/v1/bugbounty/analyze",
    json={
        "scan_id": scan_id,
        "filter_false_positives": True
    }
).json()

print(f"Analysis: {analysis['analysis']}")
print(f"AI Insights: {analysis['ai_insights']}")
```

#### Step 5: Generate Exploit

```python
# Generate exploit for first critical vulnerability
critical_vuln = [
    v for v in issues['vulnerabilities']
    if v['severity'] == 'Critical'
][0]

exploit = requests.post(
    "http://localhost:8000/api/v1/bugbounty/exploit",
    json={
        "vulnerability_id": critical_vuln['title'],
        "exploit_type": "POC"
    }
).json()

print("Exploit Code:")
print(exploit['exploit']['code'])
print("\nSteps:")
for step in exploit['exploit']['steps']:
    print(f"  - {step}")
```

#### Step 6: Generate Report

```python
# Create professional report
report = requests.post(
    "http://localhost:8000/api/v1/bugbounty/report",
    json={
        "vulnerability_ids": [critical_vuln['title']],
        "format": "markdown",
        "platform": "HackerOne"
    }
).json()

# Save report
with open(f"report_{scan_id}.md", 'w') as f:
    f.write(report['report'])

print(f"Report saved! Estimated bounty: ${report['estimated_bounty']}")
```

---

## API Reference

### Configure BurpSuite

**POST** `/api/v1/bugbounty/configure`

```json
{
  "api_url": "http://localhost:1337",
  "api_key": "optional-api-key"
}
```

### Create Program

**POST** `/api/v1/bugbounty/programs`

```json
{
  "name": "Program Name",
  "platform": "HackerOne",
  "in_scope": ["*.example.com"],
  "out_of_scope": ["*.test.example.com"],
  "no_dos": true
}
```

### Start Reconnaissance

**POST** `/api/v1/bugbounty/recon`

```json
{
  "domain": "example.com",
  "program_name": "Program Name",
  "scope": ["*.example.com"],
  "passive_only": false
}
```

### Start Scan

**POST** `/api/v1/bugbounty/scan`

```json
{
  "target_url": "https://app.example.com",
  "scan_type": "CrawlAndAudit",
  "crawl_depth": 5,
  "check_scope": true
}
```

### Get Scan Status

**GET** `/api/v1/bugbounty/scan/{scan_id}`

### Get Vulnerabilities

**GET** `/api/v1/bugbounty/scan/{scan_id}/issues`

### Analyze Vulnerabilities

**POST** `/api/v1/bugbounty/analyze`

```json
{
  "scan_id": "scan_id_here",
  "filter_false_positives": true
}
```

### Generate Exploit

**POST** `/api/v1/bugbounty/exploit`

```json
{
  "vulnerability_id": "vuln_title",
  "exploit_type": "POC"
}
```

### Generate Report

**POST** `/api/v1/bugbounty/report`

```json
{
  "vulnerability_ids": ["vuln1", "vuln2"],
  "format": "markdown",
  "platform": "HackerOne"
}
```

### Get Statistics

**GET** `/api/v1/bugbounty/stats`

### Health Check

**GET** `/api/v1/bugbounty/health`

---

## Examples

### Example 1: Quick Scan

```python
import requests

# Configure
requests.post("http://localhost:8000/api/v1/bugbounty/configure")

# Create program
requests.post("http://localhost:8000/api/v1/bugbounty/programs", json={
    "name": "Test Program",
    "in_scope": ["https://testphp.vulnweb.com"]
})

# Scan
scan = requests.post("http://localhost:8000/api/v1/bugbounty/scan", json={
    "target_url": "https://testphp.vulnweb.com",
    "scan_type": "LightActive"
}).json()

print(f"Scan ID: {scan['scan_id']}")
```

### Example 2: Full Automation Script

```python
import requests
import time

class BugBountyAutomation:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
    
    def configure(self):
        return requests.post(f"{self.base_url}/api/v1/bugbounty/configure").json()
    
    def create_program(self, name, in_scope, out_of_scope=[]):
        return requests.post(
            f"{self.base_url}/api/v1/bugbounty/programs",
            json={"name": name, "in_scope": in_scope, "out_of_scope": out_of_scope}
        ).json()
    
    def scan_target(self, url, scan_type="CrawlAndAudit"):
        return requests.post(
            f"{self.base_url}/api/v1/bugbounty/scan",
            json={"target_url": url, "scan_type": scan_type}
        ).json()
    
    def wait_for_scan(self, scan_id, timeout=3600):
        start = time.time()
        while time.time() - start < timeout:
            status = requests.get(
                f"{self.base_url}/api/v1/bugbounty/scan/{scan_id}"
            ).json()
            
            if status['scan_status'] in ['succeeded', 'failed']:
                return status
            
            time.sleep(30)
        
        raise TimeoutError("Scan timeout")
    
    def get_vulnerabilities(self, scan_id):
        return requests.get(
            f"{self.base_url}/api/v1/bugbounty/scan/{scan_id}/issues"
        ).json()
    
    def generate_report(self, vuln_ids, platform="HackerOne"):
        return requests.post(
            f"{self.base_url}/api/v1/bugbounty/report",
            json={"vulnerability_ids": vuln_ids, "format": "markdown", "platform": platform}
        ).json()

# Usage
bot = BugBountyAutomation()
bot.configure()
bot.create_program("My Program", ["*.example.com"])

scan = bot.scan_target("https://app.example.com")
scan_id = scan['scan_id']

print("Waiting for scan...")
result = bot.wait_for_scan(scan_id)

vulns = bot.get_vulnerabilities(scan_id)
print(f"Found {vulns['issues_count']} vulnerabilities")

# Generate report for critical issues
critical = [v['title'] for v in vulns['vulnerabilities'] if v['severity'] == 'Critical']
if critical:
    report = bot.generate_report(critical)
    print(f"Report saved! Bounty estimate: ${report['estimated_bounty']}")
```

---

## Best Practices

### 1. Always Verify Scope

```python
# ALWAYS check scope before testing
validator = requests.post("http://localhost:8000/api/v1/bugbounty/programs", ...)
scope_check = validator.json()['scope_summary']
print(scope_check)

# Read the warning
print(validator.json()['warning'])
```

### 2. Start with Passive Reconnaissance

```python
# Use passive_only=True first
recon = requests.post("/api/v1/bugbounty/recon", json={
    "domain": "example.com",
    "passive_only": True  # Safe, no active scanning
})
```

### 3. Use Light Scans First

```python
# Start with LightActive, not DeepScan
scan = requests.post("/api/v1/bugbounty/scan", json={
    "target_url": "...",
    "scan_type": "LightActive"  # Less intrusive
})
```

### 4. Filter False Positives

```python
# Always enable false positive filtering
analysis = requests.post("/api/v1/bugbounty/analyze", json={
    "scan_id": scan_id,
    "filter_false_positives": True  # Critical!
})
```

### 5. Test Exploits Safely

```python
# Use POC exploits only (safe, non-destructive)
exploit = requests.post("/api/v1/bugbounty/exploit", json={
    "vulnerability_id": "...",
    "exploit_type": "POC"  # Safe payloads only
})
```

### 6. Document Everything

```python
# Generate comprehensive reports
report = requests.post("/api/v1/bugbounty/report", json={
    "vulnerability_ids": [...],
    "format": "markdown",
    "platform": "HackerOne"  # Use correct platform
})
```

---

## Troubleshooting

### BurpSuite Not Connecting

**Problem**: `BurpSuite connection failed`

**Solution**:
```bash
# 1. Check BurpSuite is running
# 2. Verify REST API is enabled (User Options → Misc → REST API)
# 3. Check API URL matches
curl http://localhost:1337/v0.1/
```

### Out of Scope Error

**Problem**: `Target is OUT OF SCOPE`

**Solution**:
```python
# 1. Verify scope configuration
programs = requests.get("http://localhost:8000/api/v1/bugbounty/programs").json()
print(programs)

# 2. Update scope if needed
# 3. Or disable scope checking (NOT RECOMMENDED)
scan = requests.post("/api/v1/bugbounty/scan", json={
    "target_url": "...",
    "check_scope": False  # Use with caution!
})
```

### Scan Timeout

**Problem**: Scan takes too long

**Solution**:
```python
# Use lighter scan type
scan = requests.post("/api/v1/bugbounty/scan", json={
    "target_url": "...",
    "scan_type": "CrawlOnly",  # Faster
    "crawl_depth": 3  # Reduce depth
})
```

### No Vulnerabilities Found

**Problem**: `issues_count: 0`

**Solution**:
1. Target may be secure
2. Try deeper scan: `"scan_type": "DeepScan"`
3. Increase crawl depth: `"crawl_depth": 10`
4. Check BurpSuite configuration (audit checks enabled)

---

## Advanced Features

### Custom Scan Configuration

```python
# Advanced scan with custom settings
scan = requests.post("/api/v1/bugbounty/scan", json={
    "target_url": "https://app.example.com",
    "scan_type": "DeepScan",
    "crawl_depth": 10,
    "check_scope": True
})
```

### Chaining Exploits

```python
# Use AI to chain multiple vulnerabilities
analysis = requests.post("/api/v1/bugbounty/analyze", json={
    "scan_id": scan_id,
    "filter_false_positives": True
}).json()

# AI will suggest exploitation chains
for insight in analysis['ai_insights']:
    print(insight['attack_chains'])
```

### Platform-Specific Reports

```python
# Generate report for specific platform
report = requests.post("/api/v1/bugbounty/report", json={
    "vulnerability_ids": [...],
    "format": "markdown",
    "platform": "Bugcrowd"  # HackerOne, Bugcrowd, Intigriti
}).json()
```

---

## Legal & Ethical Guidelines

### ✅ DO:
- Test only authorized targets
- Follow bug bounty program rules
- Respect scope boundaries
- Use safe, non-destructive payloads
- Submit findings responsibly
- Wait for program response before disclosure

### ❌ DON'T:
- Test without authorization
- Perform DoS attacks
- Access sensitive data unnecessarily
- Share vulnerabilities publicly before fix
- Use findings for malicious purposes
- Test out-of-scope assets

---

## Support

### Resources
- **BurpSuite Docs**: https://portswigger.net/burp/documentation
- **HackerOne Disclosure**: https://www.hackerone.com/disclosure-guidelines
- **Bugcrowd VDP**: https://www.bugcrowd.com/programs/

### Contact
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Security**: security@example.com (for Aether AI vulnerabilities)

---

## License

This feature is part of Aether AI and is licensed under MIT License.

**DISCLAIMER**: This tool is for authorized security testing only. Misuse is illegal and unethical. Users are solely responsible for their actions.
