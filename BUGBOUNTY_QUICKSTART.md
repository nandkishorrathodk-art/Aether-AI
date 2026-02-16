# Bug Bounty Automation - Quick Start Guide

## What is This?

Aether AI now includes **automated bug bounty hunting** with BurpSuite integration and AI-powered vulnerability analysis. This allows you to automate security testing for authorized bug bounty programs.

## ⚠️ CRITICAL WARNING

**ONLY use on authorized targets:**
- ✅ Bug bounty programs (HackerOne, Bugcrowd, Intigriti)
- ✅ Penetration tests with written permission
- ✅ Your own applications
- ❌ NEVER test without authorization (illegal!)

## Quick Test

```bash
# Test the bug bounty features
test-bugbounty.bat
```

This runs 7 test scenarios:
1. Scope Validator
2. Scope Manager
3. Reconnaissance Engine
4. Vulnerability Analyzer
5. Exploit Generator
6. Report Generator
7. BurpSuite Integration

## Features

### 🔍 Reconnaissance
- Passive subdomain enumeration
- Technology detection
- Port scanning
- Asset discovery

### 🛡️ BurpSuite Integration
- Automated security scanning
- Real-time monitoring
- Vulnerability extraction
- Professional-grade results

### 🧠 AI Analysis
- 18+ vulnerability types
- False positive filtering
- CVSS scoring
- Attack vector suggestions

### 💥 Exploit Generation
- Safe POC exploits
- Python/cURL/Bash formats
- WAF bypass techniques
- Step-by-step guides

### 📝 Professional Reports
- HackerOne/Bugcrowd/Intigriti templates
- Markdown/HTML/JSON formats
- AI-enhanced quality
- Bounty estimation

### ✅ Safety Features
- Automatic scope validation
- Out-of-scope blocking
- Non-destructive payloads
- Ethical warnings

## Basic Usage

### 1. Start Aether AI Backend

```bash
start-aether.bat
```

### 2. Configure Program (Python Example)

```python
import requests

base = "http://localhost:8000/api/v1/bugbounty"

# Create program
requests.post(f"{base}/programs", json={
    "name": "Example Corp",
    "platform": "HackerOne",
    "in_scope": ["*.example.com"],
    "out_of_scope": ["*.test.example.com"]
})
```

### 3. Start Reconnaissance

```python
# Recon
recon = requests.post(f"{base}/recon", json={
    "domain": "example.com",
    "program_name": "Example Corp"
})

# Get results
target_id = recon.json()["target_id"]
results = requests.get(f"{base}/recon/{target_id}").json()
print(f"Found {results['subdomains_count']} subdomains")
```

### 4. Scan with BurpSuite (requires BurpSuite Pro)

```python
# Configure BurpSuite first
requests.post(f"{base}/configure", json={
    "api_url": "http://localhost:1337"
})

# Start scan
scan = requests.post(f"{base}/scan", json={
    "target_url": "https://app.example.com",
    "scan_type": "CrawlAndAudit"
})

scan_id = scan.json()["scan_id"]
```

### 5. Analyze Vulnerabilities

```python
# Get vulnerabilities
vulns = requests.get(f"{base}/scan/{scan_id}/issues").json()

# AI analysis
analysis = requests.post(f"{base}/analyze", json={
    "scan_id": scan_id,
    "filter_false_positives": True
}).json()

print(f"Found {vulns['issues_count']} vulnerabilities")
```

### 6. Generate Report

```python
# Get critical vulnerabilities
critical = [v['title'] for v in vulns['vulnerabilities'] 
            if v['severity'] == 'Critical']

# Generate report
report = requests.post(f"{base}/report", json={
    "vulnerability_ids": critical,
    "format": "markdown",
    "platform": "HackerOne"
}).json()

# Save report
with open("report.md", "w") as f:
    f.write(report['report'])
```

## API Endpoints

- `POST /api/v1/bugbounty/configure` - Configure BurpSuite
- `POST /api/v1/bugbounty/programs` - Create program
- `POST /api/v1/bugbounty/recon` - Start reconnaissance
- `POST /api/v1/bugbounty/scan` - Start scan
- `GET /api/v1/bugbounty/scan/{id}/issues` - Get vulnerabilities
- `POST /api/v1/bugbounty/analyze` - Analyze vulnerabilities
- `POST /api/v1/bugbounty/exploit` - Generate exploit
- `POST /api/v1/bugbounty/report` - Generate report
- `GET /api/v1/bugbounty/stats` - Get statistics
- `GET /api/v1/bugbounty/health` - Health check

## Requirements

### Optional: BurpSuite Professional
- For automated scanning features
- Download: https://portswigger.net/burp/pro
- Enable REST API (User Options → Misc → REST API)
- Default API URL: http://localhost:1337

### Already Included
- Python dependencies (dnspython)
- AI providers for analysis
- Reconnaissance tools

## Documentation

📖 **Complete Guide**: [docs/BUGBOUNTY_AUTOMATION.md](./docs/BUGBOUNTY_AUTOMATION.md)
📖 **Implementation Details**: [docs/BUGBOUNTY_SUMMARY.md](./docs/BUGBOUNTY_SUMMARY.md)

## Examples

### Test Script
See `scripts/test_bugbounty.py` for working examples of all features.

### Automated Workflow

```python
# Complete automation example
class BugBountyBot:
    def __init__(self):
        self.base = "http://localhost:8000/api/v1/bugbounty"
    
    def hunt(self, domain, program_name, in_scope):
        # 1. Create program
        requests.post(f"{self.base}/programs", json={
            "name": program_name,
            "in_scope": in_scope
        })
        
        # 2. Recon
        recon = requests.post(f"{self.base}/recon", json={
            "domain": domain,
            "program_name": program_name
        }).json()
        
        # 3. Scan (requires BurpSuite)
        scan = requests.post(f"{self.base}/scan", json={
            "target_url": f"https://{domain}"
        }).json()
        
        # 4. Wait and analyze
        # ... (add polling logic)
        
        # 5. Generate report
        # ... (get vulnerabilities and create report)

# Usage
bot = BugBountyBot()
bot.hunt("example.com", "Example Corp", ["*.example.com"])
```

## Safety Checklist

Before testing:
- [ ] Target is in authorized program
- [ ] Scope is properly configured
- [ ] Read program rules
- [ ] No DoS testing (unless allowed)
- [ ] Report through proper channels
- [ ] Follow responsible disclosure

## Troubleshooting

### BurpSuite Connection Failed
- Ensure BurpSuite Professional is running
- Enable REST API in settings
- Check API URL (default: http://localhost:1337)

### Out of Scope Error
- Verify target matches program scope
- Check wildcard patterns (*.example.com)
- Review out-of-scope rules

### No Vulnerabilities Found
- Target may be secure
- Try deeper scan: `"scan_type": "DeepScan"`
- Check BurpSuite audit checks enabled

## Support

- **Documentation**: docs/BUGBOUNTY_AUTOMATION.md
- **Test Suite**: test-bugbounty.bat
- **API Docs**: http://localhost:8000/docs (when running)

---

**Remember**: This tool is for authorized security testing only. Misuse is illegal and unethical. Always get permission before testing.
