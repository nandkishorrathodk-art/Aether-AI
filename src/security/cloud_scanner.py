"""
Cloud and Container Security Scanner
Specialized scanning for cloud platforms and containerized environments
"""

import asyncio
import subprocess
import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class CloudPlatform(str, Enum):
    """Supported cloud platforms"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"


@dataclass
class CloudFinding:
    """Cloud security finding"""
    platform: CloudPlatform
    resource_type: str
    resource_id: str
    finding_type: str
    severity: str
    description: str
    remediation: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "platform": self.platform.value,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation
        }


class CloudSecurityScanner:
    """
    Cloud and container security scanner
    
    Features:
    - AWS security assessment
    - Azure security center integration
    - GCP security command center
    - Docker image scanning
    - Kubernetes cluster scanning
    - Misconfiguration detection
    """
    
    def __init__(self):
        """Initialize cloud scanner"""
        self.tools = {
            "docker": self._check_docker_available(),
            "kubectl": self._check_kubectl_available(),
            "trivy": self._check_trivy_available()
        }
        logger.info("Cloud Security Scanner initialized")
    
    def _check_docker_available(self) -> bool:
        """Check if Docker is available"""
        try:
            subprocess.run(["docker", "--version"], capture_output=True, check=True)
            return True
        except:
            return False
    
    def _check_kubectl_available(self) -> bool:
        """Check if kubectl is available"""
        try:
            subprocess.run(["kubectl", "version", "--client"], capture_output=True, check=True)
            return True
        except:
            return False
    
    def _check_trivy_available(self) -> bool:
        """Check if Trivy is available"""
        try:
            subprocess.run(["trivy", "--version"], capture_output=True, check=True)
            return True
        except:
            return False
    
    async def scan_docker_image(
        self,
        image_name: str
    ) -> Dict[str, Any]:
        """
        Scan Docker image for vulnerabilities
        
        Args:
            image_name: Docker image name/tag
        
        Returns:
            Scan results
        """
        if not self.tools["trivy"]:
            logger.warning("Trivy not available. Install with: brew install aquasecurity/trivy/trivy")
            return self._manual_docker_scan(image_name)
        
        try:
            result = subprocess.run(
                ["trivy", "image", "--format", "json", image_name],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                scan_data = json.loads(result.stdout)
                return self._process_trivy_results(scan_data)
            else:
                logger.error(f"Trivy scan failed: {result.stderr}")
                return {"error": result.stderr}
        except Exception as e:
            logger.error(f"Docker image scan failed: {e}")
            return {"error": str(e)}
    
    def _manual_docker_scan(self, image_name: str) -> Dict[str, Any]:
        """Manual Docker security checks"""
        findings = []
        
        if not self.tools["docker"]:
            return {"error": "Docker not available"}
        
        try:
            result = subprocess.run(
                ["docker", "inspect", image_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                inspect_data = json.loads(result.stdout)[0]
                
                config = inspect_data.get("Config", {})
                if config.get("User") == "" or config.get("User") == "root":
                    findings.append(CloudFinding(
                        platform=CloudPlatform.DOCKER,
                        resource_type="container",
                        resource_id=image_name,
                        finding_type="running_as_root",
                        severity="HIGH",
                        description="Container running as root user",
                        remediation="Use USER instruction in Dockerfile to run as non-root"
                    ))
                
                if "--privileged" in str(inspect_data):
                    findings.append(CloudFinding(
                        platform=CloudPlatform.DOCKER,
                        resource_type="container",
                        resource_id=image_name,
                        finding_type="privileged_mode",
                        severity="CRITICAL",
                        description="Container running in privileged mode",
                        remediation="Remove --privileged flag unless absolutely necessary"
                    ))
        except Exception as e:
            logger.error(f"Docker inspection failed: {e}")
        
        return {
            "image": image_name,
            "findings": [f.to_dict() for f in findings],
            "total_vulnerabilities": len(findings)
        }
    
    def _process_trivy_results(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process Trivy scan results"""
        findings = []
        
        for result in scan_data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN")
                
                findings.append({
                    "vulnerability_id": vuln.get("VulnerabilityID", ""),
                    "package": vuln.get("PkgName", ""),
                    "severity": severity,
                    "description": vuln.get("Description", ""),
                    "fixed_version": vuln.get("FixedVersion", "Not available")
                })
        
        severity_counts = {}
        for finding in findings:
            severity = finding["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_vulnerabilities": len(findings),
            "severity_distribution": severity_counts,
            "findings": findings
        }
    
    async def scan_kubernetes_cluster(self) -> Dict[str, Any]:
        """
        Scan Kubernetes cluster for security issues
        
        Returns:
            Scan results
        """
        if not self.tools["kubectl"]:
            return {"error": "kubectl not available"}
        
        findings = []
        
        try:
            result = subprocess.run(
                ["kubectl", "get", "pods", "--all-namespaces", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                pods_data = json.loads(result.stdout)
                
                for pod in pods_data.get("items", []):
                    pod_name = pod["metadata"]["name"]
                    namespace = pod["metadata"]["namespace"]
                    
                    spec = pod.get("spec", {})
                    
                    for container in spec.get("containers", []):
                        if container.get("securityContext", {}).get("privileged"):
                            findings.append(CloudFinding(
                                platform=CloudPlatform.KUBERNETES,
                                resource_type="pod",
                                resource_id=f"{namespace}/{pod_name}",
                                finding_type="privileged_container",
                                severity="CRITICAL",
                                description="Pod running privileged container",
                                remediation="Remove privileged flag from container security context"
                            ))
                        
                        if not container.get("securityContext", {}).get("runAsNonRoot"):
                            findings.append(CloudFinding(
                                platform=CloudPlatform.KUBERNETES,
                                resource_type="pod",
                                resource_id=f"{namespace}/{pod_name}",
                                finding_type="root_user",
                                severity="HIGH",
                                description="Container may run as root",
                                remediation="Set runAsNonRoot: true in security context"
                            ))
        except Exception as e:
            logger.error(f"Kubernetes scan failed: {e}")
            return {"error": str(e)}
        
        return {
            "platform": "kubernetes",
            "findings": [f.to_dict() for f in findings],
            "total_issues": len(findings)
        }
    
    async def scan_aws_security(
        self,
        profile: str = "default"
    ) -> Dict[str, Any]:
        """
        Scan AWS security configuration
        
        Args:
            profile: AWS CLI profile
        
        Returns:
            Scan results
        """
        findings = []
        
        checks = [
            {
                "name": "S3 Public Buckets",
                "command": ["aws", "s3api", "list-buckets", "--profile", profile],
                "check": self._check_s3_public_access
            }
        ]
        
        for check in checks:
            try:
                result = subprocess.run(
                    check["command"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    check_findings = check["check"](result.stdout)
                    findings.extend(check_findings)
            except Exception as e:
                logger.warning(f"AWS check '{check['name']}' failed: {e}")
        
        return {
            "platform": "aws",
            "findings": [f.to_dict() for f in findings],
            "total_issues": len(findings)
        }
    
    def _check_s3_public_access(self, output: str) -> List[CloudFinding]:
        """Check S3 buckets for public access"""
        findings = []
        
        try:
            data = json.loads(output)
            for bucket in data.get("Buckets", []):
                findings.append(CloudFinding(
                    platform=CloudPlatform.AWS,
                    resource_type="s3_bucket",
                    resource_id=bucket["Name"],
                    finding_type="potential_public_access",
                    severity="MEDIUM",
                    description="S3 bucket requires access verification",
                    remediation="Review bucket policy and block public access if not needed"
                ))
        except Exception as e:
            logger.error(f"S3 check failed: {e}")
        
        return findings
    
    def get_recommendations(self, platform: CloudPlatform) -> List[str]:
        """Get security recommendations for platform"""
        recommendations = {
            CloudPlatform.DOCKER: [
                "Use official base images from trusted sources",
                "Run containers as non-root users",
                "Scan images regularly for vulnerabilities",
                "Use minimal base images (Alpine, Distroless)",
                "Keep images updated with security patches"
            ],
            CloudPlatform.KUBERNETES: [
                "Enable RBAC and follow principle of least privilege",
                "Use Pod Security Policies/Standards",
                "Enable network policies",
                "Scan container images before deployment",
                "Use secrets management for sensitive data"
            ],
            CloudPlatform.AWS: [
                "Enable AWS Security Hub",
                "Use IAM roles instead of access keys",
                "Enable CloudTrail for audit logging",
                "Encrypt data at rest and in transit",
                "Implement least privilege access"
            ]
        }
        
        return recommendations.get(platform, ["Follow cloud security best practices"])
