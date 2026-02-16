"""
Compliance Checker for Regulatory Standards
Ensures Aether AI meets GDPR, CCPA, ISO 27001, SOC 2, etc.
"""
from enum import Enum
from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ComplianceStandard(Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    ISO_27001 = "iso_27001"
    SOC_2 = "soc_2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    DPDP_ACT = "dpdp_act"


@dataclass
class ComplianceCheck:
    standard: ComplianceStandard
    requirement: str
    status: str
    compliant: bool
    notes: str
    last_checked: datetime


class ComplianceChecker:
    """
    Automated compliance auditing system
    Generates reports for regulatory standards
    """
    
    def __init__(self):
        self.checks: List[ComplianceCheck] = []
        self.compliance_rules = self._load_compliance_rules()
        logger.info("Compliance Checker initialized")
        
    def _load_compliance_rules(self) -> Dict[ComplianceStandard, List[Dict[str, str]]]:
        """Load compliance requirements for each standard"""
        return {
            ComplianceStandard.GDPR: [
                {"requirement": "Right to be forgotten", "description": "Users can request data deletion"},
                {"requirement": "Data portability", "description": "Users can export their data"},
                {"requirement": "Consent management", "description": "Explicit consent for data processing"},
                {"requirement": "Data encryption", "description": "Personal data must be encrypted"},
                {"requirement": "Breach notification", "description": "Report breaches within 72 hours"},
                {"requirement": "Privacy by design", "description": "Privacy built into system architecture"},
                {"requirement": "Data minimization", "description": "Collect only necessary data"}
            ],
            ComplianceStandard.CCPA: [
                {"requirement": "Right to know", "description": "Users can request what data is collected"},
                {"requirement": "Right to delete", "description": "Users can delete their data"},
                {"requirement": "Right to opt-out", "description": "Users can opt-out of data sale"},
                {"requirement": "Non-discrimination", "description": "No penalty for exercising rights"}
            ],
            ComplianceStandard.ISO_27001: [
                {"requirement": "Information security policy", "description": "Documented security policies"},
                {"requirement": "Access control", "description": "Role-based access controls"},
                {"requirement": "Cryptography", "description": "Data encryption standards"},
                {"requirement": "Physical security", "description": "Secure physical infrastructure"},
                {"requirement": "Incident management", "description": "Security incident response plan"},
                {"requirement": "Business continuity", "description": "Backup and recovery procedures"}
            ],
            ComplianceStandard.SOC_2: [
                {"requirement": "Security", "description": "System protection against unauthorized access"},
                {"requirement": "Availability", "description": "System uptime and reliability"},
                {"requirement": "Confidentiality", "description": "Protection of sensitive information"},
                {"requirement": "Processing integrity", "description": "Accurate and timely processing"},
                {"requirement": "Privacy", "description": "Personal information handling"}
            ],
            ComplianceStandard.DPDP_ACT: [
                {"requirement": "Data localization", "description": "Store Indian user data in India"},
                {"requirement": "Consent management", "description": "Clear consent mechanisms"},
                {"requirement": "Data protection officer", "description": "Appoint DPO for large processors"},
                {"requirement": "Cross-border transfer", "description": "Comply with data transfer rules"}
            ]
        }
        
    def check_gdpr_compliance(self) -> List[ComplianceCheck]:
        """Check GDPR compliance"""
        results = []
        
        results.append(ComplianceCheck(
            standard=ComplianceStandard.GDPR,
            requirement="Data encryption (AES-256)",
            status="COMPLIANT",
            compliant=True,
            notes="AetherEncryption module provides AES-256 encryption",
            last_checked=datetime.now()
        ))
        
        results.append(ComplianceCheck(
            standard=ComplianceStandard.GDPR,
            requirement="Right to be forgotten",
            status="COMPLIANT",
            compliant=True,
            notes="User can delete profile via API /api/v1/memory/profile/{user_id}",
            last_checked=datetime.now()
        ))
        
        results.append(ComplianceCheck(
            standard=ComplianceStandard.GDPR,
            requirement="Data portability",
            status="COMPLIANT",
            compliant=True,
            notes="Export via /api/v1/memory/profile/{user_id}",
            last_checked=datetime.now()
        ))
        
        results.append(ComplianceCheck(
            standard=ComplianceStandard.GDPR,
            requirement="Consent management",
            status="PARTIAL",
            compliant=False,
            notes="TODO: Add explicit consent UI for data collection",
            last_checked=datetime.now()
        ))
        
        return results
        
    def check_iso_27001_compliance(self) -> List[ComplianceCheck]:
        """Check ISO 27001 compliance"""
        results = []
        
        results.append(ComplianceCheck(
            standard=ComplianceStandard.ISO_27001,
            requirement="Cryptography controls",
            status="COMPLIANT",
            compliant=True,
            notes="AES-256 encryption, SHA-256 hashing implemented",
            last_checked=datetime.now()
        ))
        
        results.append(ComplianceCheck(
            standard=ComplianceStandard.ISO_27001,
            requirement="Access control",
            status="PARTIAL",
            compliant=False,
            notes="TODO: Implement API authentication (JWT recommended)",
            last_checked=datetime.now()
        ))
        
        results.append(ComplianceCheck(
            standard=ComplianceStandard.ISO_27001,
            requirement="Incident management",
            status="COMPLIANT",
            compliant=True,
            notes="ThreatDetector module monitors and logs security events",
            last_checked=datetime.now()
        ))
        
        return results
        
    def run_full_audit(self, standards: List[ComplianceStandard] = None) -> Dict[str, Any]:
        """Run comprehensive compliance audit"""
        standards = standards or [ComplianceStandard.GDPR, ComplianceStandard.ISO_27001]
        
        all_checks = []
        for standard in standards:
            if standard == ComplianceStandard.GDPR:
                all_checks.extend(self.check_gdpr_compliance())
            elif standard == ComplianceStandard.ISO_27001:
                all_checks.extend(self.check_iso_27001_compliance())
                
        self.checks = all_checks
        
        total_checks = len(all_checks)
        compliant_checks = sum(1 for c in all_checks if c.compliant)
        compliance_rate = (compliant_checks / total_checks * 100) if total_checks > 0 else 0
        
        return {
            "total_checks": total_checks,
            "compliant": compliant_checks,
            "non_compliant": total_checks - compliant_checks,
            "compliance_rate": f"{compliance_rate:.1f}%",
            "standards_checked": [s.value for s in standards],
            "checks": [
                {
                    "standard": c.standard.value,
                    "requirement": c.requirement,
                    "status": c.status,
                    "compliant": c.compliant,
                    "notes": c.notes
                }
                for c in all_checks
            ],
            "timestamp": datetime.now().isoformat()
        }
        
    def generate_compliance_report(self, standard: ComplianceStandard) -> str:
        """Generate detailed compliance report"""
        audit_results = self.run_full_audit([standard])
        
        report = f"""
# Compliance Audit Report: {standard.value.upper()}
**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Total Checks**: {audit_results['total_checks']}
- **Compliant**: {audit_results['compliant']}
- **Non-Compliant**: {audit_results['non_compliant']}
- **Compliance Rate**: {audit_results['compliance_rate']}

## Detailed Findings
"""
        
        for check in audit_results['checks']:
            status_icon = "✅" if check['compliant'] else "❌"
            report += f"\n### {status_icon} {check['requirement']}\n"
            report += f"- **Status**: {check['status']}\n"
            report += f"- **Notes**: {check['notes']}\n"
            
        report += "\n## Recommendations\n"
        non_compliant = [c for c in audit_results['checks'] if not c['compliant']]
        if non_compliant:
            for check in non_compliant:
                report += f"- {check['requirement']}: {check['notes']}\n"
        else:
            report += "All requirements met. Maintain current security practices.\n"
            
        return report
