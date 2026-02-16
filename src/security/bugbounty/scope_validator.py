"""
Scope Validator

Validates targets against bug bounty program scope rules.
Prevents testing out-of-scope assets and ensures ethical boundaries.
Critical safety component for responsible bug bounty hunting.
"""

import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse
import fnmatch
import logging

logger = logging.getLogger(__name__)


@dataclass
class Program:
    """Bug bounty program configuration"""
    name: str
    platform: str  # HackerOne, Bugcrowd, etc.
    
    # Scope rules
    in_scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    
    # Asset types
    scope_types: List[str] = field(default_factory=list)  # web, api, mobile, etc.
    
    # Rules
    requires_auth: bool = False
    no_dos: bool = True
    no_social_engineering: bool = True
    no_phishing: bool = True
    no_physical_access: bool = True
    
    # Additional rules
    custom_rules: List[str] = field(default_factory=list)
    
    # Contact
    contact_email: Optional[str] = None
    disclosure_policy: Optional[str] = None


class ScopeValidator:
    """
    Validates targets against program scope
    
    Features:
    - Wildcard domain matching
    - IP range validation
    - Path-based scoping
    - Subdomain validation
    - Automated scope checking
    - Safety warnings for out-of-scope testing
    """
    
    def __init__(self, program: Optional[Program] = None):
        """
        Initialize scope validator
        
        Args:
            program: Bug bounty program configuration
        """
        self.program = program
        self.tested_targets: Set[str] = set()
        self.warnings: List[str] = []
    
    def is_in_scope(self, target: str) -> bool:
        """
        Check if target is in scope
        
        Args:
            target: URL, domain, or IP to check
            
        Returns:
            True if in scope, False otherwise
        """
        if not self.program:
            logger.warning("No program configured - cannot validate scope")
            return False
        
        # Normalize target
        target = target.lower().strip()
        
        # Check if explicitly out of scope
        if self._matches_any(target, self.program.out_of_scope):
            logger.warning(f"Target {target} is OUT OF SCOPE")
            return False
        
        # Check if in scope
        if self._matches_any(target, self.program.in_scope):
            logger.info(f"Target {target} is IN SCOPE")
            return True
        
        logger.warning(f"Target {target} does not match scope")
        return False
    
    def _matches_any(self, target: str, patterns: List[str]) -> bool:
        """Check if target matches any pattern"""
        for pattern in patterns:
            if self._matches_pattern(target, pattern):
                return True
        return False
    
    def _matches_pattern(self, target: str, pattern: str) -> bool:
        """
        Check if target matches pattern
        
        Supports:
        - Exact match: example.com
        - Wildcard subdomain: *.example.com
        - Path matching: example.com/api/*
        - IP ranges: 192.168.1.0/24
        """
        pattern = pattern.lower().strip()
        
        # Extract domain from URL if needed
        if target.startswith('http://') or target.startswith('https://'):
            parsed = urlparse(target)
            domain = parsed.netloc
            path = parsed.path
        else:
            domain = target
            path = '/'
        
        # Extract domain from pattern if needed
        if pattern.startswith('http://') or pattern.startswith('https://'):
            parsed = urlparse(pattern)
            pattern_domain = parsed.netloc
            pattern_path = parsed.path
        else:
            pattern_domain = pattern.split('/')[0]
            pattern_path = '/' + '/'.join(pattern.split('/')[1:]) if '/' in pattern else '/'
        
        # Domain matching
        if pattern_domain.startswith('*.'):
            # Wildcard subdomain
            base_domain = pattern_domain[2:]
            if domain == base_domain or domain.endswith('.' + base_domain):
                # Check path if pattern has path
                if pattern_path != '/':
                    return fnmatch.fnmatch(path, pattern_path)
                return True
        else:
            # Exact domain match
            if domain == pattern_domain:
                # Check path if pattern has path
                if pattern_path != '/':
                    return fnmatch.fnmatch(path, pattern_path)
                return True
        
        # IP range matching (basic)
        if '/' in pattern:  # CIDR notation
            # Simplified - in production use ipaddress module
            base_ip = pattern.split('/')[0]
            if target.startswith(base_ip.rsplit('.', 1)[0]):
                return True
        
        return False
    
    def validate_url(self, url: str) -> Dict[str, any]:
        """
        Validate URL and return detailed scope information
        
        Args:
            url: URL to validate
            
        Returns:
            Dict with validation results
        """
        result = {
            "url": url,
            "in_scope": False,
            "warnings": [],
            "recommendations": []
        }
        
        if not self.program:
            result["warnings"].append("No program configured")
            return result
        
        # Check scope
        result["in_scope"] = self.is_in_scope(url)
        
        if not result["in_scope"]:
            result["warnings"].append("Target is OUT OF SCOPE or does not match program scope")
            result["recommendations"].append("Do NOT test this target")
            result["recommendations"].append("Review program scope rules")
        
        # Check for common issues
        parsed = urlparse(url)
        
        # Localhost/internal IPs
        if parsed.netloc in ['localhost', '127.0.0.1', '0.0.0.0']:
            result["warnings"].append("Localhost address detected")
        
        # Private IP ranges
        if parsed.netloc.startswith(('192.168.', '10.', '172.')):
            result["warnings"].append("Private IP address detected")
        
        # Non-standard ports
        if ':' in parsed.netloc and parsed.netloc.split(':')[1] not in ['80', '443']:
            result["warnings"].append(f"Non-standard port detected: {parsed.netloc.split(':')[1]}")
        
        # Add to tested targets
        if result["in_scope"]:
            self.tested_targets.add(url)
        
        return result
    
    def check_test_type_allowed(self, test_type: str) -> bool:
        """
        Check if test type is allowed by program
        
        Args:
            test_type: Type of test (dos, social_engineering, etc.)
            
        Returns:
            True if allowed, False otherwise
        """
        if not self.program:
            return False
        
        test_type = test_type.lower()
        
        if test_type == "dos" and self.program.no_dos:
            logger.warning("DoS testing is NOT allowed")
            return False
        
        if test_type == "social_engineering" and self.program.no_social_engineering:
            logger.warning("Social engineering is NOT allowed")
            return False
        
        if test_type == "phishing" and self.program.no_phishing:
            logger.warning("Phishing is NOT allowed")
            return False
        
        if test_type == "physical" and self.program.no_physical_access:
            logger.warning("Physical access testing is NOT allowed")
            return False
        
        return True
    
    def get_scope_summary(self) -> Dict[str, any]:
        """Get summary of program scope"""
        if not self.program:
            return {"error": "No program configured"}
        
        return {
            "program": self.program.name,
            "platform": self.program.platform,
            "in_scope_count": len(self.program.in_scope),
            "out_of_scope_count": len(self.program.out_of_scope),
            "in_scope": self.program.in_scope,
            "out_of_scope": self.program.out_of_scope,
            "allowed_types": self.program.scope_types,
            "restrictions": {
                "no_dos": self.program.no_dos,
                "no_social_engineering": self.program.no_social_engineering,
                "no_phishing": self.program.no_phishing,
                "requires_auth": self.program.requires_auth
            },
            "tested_targets": len(self.tested_targets)
        }
    
    def generate_scope_warning(self) -> str:
        """Generate scope warning message"""
        if not self.program:
            return "[WARNING] No bug bounty program configured!\nDo NOT test any targets without proper authorization."
        
        warning = f"""
{'=' * 60}
[WARNING] BUG BOUNTY SCOPE VALIDATION
{'=' * 60}

Program: {self.program.name}
Platform: {self.program.platform}

IN SCOPE:
{chr(10).join(f'  [OK] {scope}' for scope in self.program.in_scope)}

OUT OF SCOPE:
{chr(10).join(f'  [X] {scope}' for scope in self.program.out_of_scope)}

RULES:
  - DoS testing: {'NOT ALLOWED' if self.program.no_dos else 'Allowed'}
  - Social Engineering: {'NOT ALLOWED' if self.program.no_social_engineering else 'Allowed'}
  - Authentication: {'Required' if self.program.requires_auth else 'Not required'}

{'=' * 60}
[WARNING] ONLY test targets that are IN SCOPE
[WARNING] Follow responsible disclosure guidelines
[WARNING] Report vulnerabilities through proper channels
{'=' * 60}
"""
        return warning


class ScopeManager:
    """Manages multiple bug bounty programs"""
    
    def __init__(self):
        self.programs: Dict[str, Program] = {}
        self.active_program: Optional[str] = None
    
    def add_program(self, program: Program):
        """Add a program"""
        self.programs[program.name] = program
        logger.info(f"Added program: {program.name}")
    
    def set_active_program(self, program_name: str):
        """Set active program"""
        if program_name in self.programs:
            self.active_program = program_name
            logger.info(f"Active program set to: {program_name}")
        else:
            logger.error(f"Program not found: {program_name}")
    
    def get_validator(self, program_name: Optional[str] = None) -> ScopeValidator:
        """Get validator for program"""
        if program_name is None:
            program_name = self.active_program
        
        if program_name and program_name in self.programs:
            return ScopeValidator(self.programs[program_name])
        else:
            logger.warning("No program specified or found")
            return ScopeValidator()
    
    def list_programs(self) -> List[str]:
        """List all programs"""
        return list(self.programs.keys())
    
    def load_from_config(self, config: Dict[str, any]):
        """Load programs from configuration"""
        for prog_config in config.get('programs', []):
            program = Program(
                name=prog_config['name'],
                platform=prog_config.get('platform', 'Custom'),
                in_scope=prog_config.get('in_scope', []),
                out_of_scope=prog_config.get('out_of_scope', []),
                scope_types=prog_config.get('scope_types', ['web']),
                no_dos=prog_config.get('no_dos', True),
                no_social_engineering=prog_config.get('no_social_engineering', True),
                contact_email=prog_config.get('contact_email')
            )
            self.add_program(program)


# Example usage
if __name__ == "__main__":
    # Create a sample program
    program = Program(
        name="Example Corp Bug Bounty",
        platform="HackerOne",
        in_scope=[
            "*.example.com",
            "example.com",
            "api.example.com",
            "app.example.com/api/*"
        ],
        out_of_scope=[
            "admin.example.com",
            "internal.example.com",
            "*.dev.example.com"
        ],
        scope_types=["web", "api"],
        no_dos=True,
        no_social_engineering=True,
        contact_email="security@example.com"
    )
    
    # Create validator
    validator = ScopeValidator(program)
    
    # Print scope warning
    print(validator.generate_scope_warning())
    
    # Test targets
    test_targets = [
        "https://example.com",
        "https://api.example.com/v1/users",
        "https://test.example.com",
        "https://admin.example.com",  # Out of scope
        "https://evil.com"  # Out of scope
    ]
    
    print("\nTesting targets:")
    print("=" * 60)
    
    for target in test_targets:
        result = validator.validate_url(target)
        status = "✅ IN SCOPE" if result["in_scope"] else "❌ OUT OF SCOPE"
        print(f"{status}: {target}")
        
        if result["warnings"]:
            for warning in result["warnings"]:
                print(f"  ⚠️  {warning}")
    
    print("\nScope Summary:")
    print("=" * 60)
    summary = validator.get_scope_summary()
    print(f"Program: {summary['program']}")
    print(f"Tested targets: {summary['tested_targets']}")
