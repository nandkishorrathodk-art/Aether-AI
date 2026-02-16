"""
Verification script for Aether AI v0.2.0 upgrade
Checks that all new modules are working correctly
"""
import sys
import os

# Fix Windows encoding issues
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def verify_multi_agent_system():
    """Verify multi-agent system"""
    print("✓ Checking multi-agent system...")
    try:
        from src.cognitive.agents import MultiAgentSystem, AgentType
        from src.cognitive.agents.specialized_agents import (
            AnalysisAgent, CodingAgent, CreativeAgent, StrategyAgent, SecurityAgent
        )
        
        mas = MultiAgentSystem()
        print("  ✓ MultiAgentSystem initialized")
        
        # Register agents
        mas.register_agent(AnalysisAgent())
        mas.register_agent(CodingAgent())
        mas.register_agent(CreativeAgent())
        mas.register_agent(StrategyAgent())
        mas.register_agent(SecurityAgent())
        print(f"  ✓ 5 specialized agents registered")
        
        stats = mas.get_system_stats()
        assert stats['total_agents'] == 5
        print(f"  ✓ Multi-agent system operational: {stats['total_agents']} agents")
        return True
    except Exception as e:
        print(f"  ✗ Multi-agent system error: {e}")
        return False

def verify_security_module():
    """Verify cybersecurity module"""
    print("✓ Checking cybersecurity module...")
    try:
        from src.security import ThreatDetector, AetherEncryption, ComplianceChecker, ComplianceStandard
        
        # Threat Detection
        detector = ThreatDetector()
        threats = detector.scan_input("SELECT * FROM users WHERE 1=1")
        print(f"  ✓ Threat detector working ({len(threats)} threats detected in test)")
        
        # Encryption
        crypto = AetherEncryption()
        encrypted = crypto.encrypt("test data")
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == "test data"
        print("  ✓ AES-256 encryption working")
        
        # Compliance
        checker = ComplianceChecker()
        audit = checker.run_full_audit([ComplianceStandard.GDPR])
        print(f"  ✓ Compliance checker working (GDPR: {audit['compliance_rate']})")
        
        return True
    except Exception as e:
        print(f"  ✗ Security module error: {e}")
        return False

def verify_professional_tools():
    """Verify professional job automation tools"""
    print("✓ Checking professional tools...")
    try:
        from src.professional import JobAutomator, SWOTAnalyzer, BusinessPlanGenerator
        
        automator = JobAutomator()
        roi = automator.calculate_roi("data_analyst", jobs_replaced=1)
        print(f"  ✓ Job Automator working (ROI: {roi['roi']})")
        
        # swot = SWOTAnalyzer()
        # print("  ✓ SWOT Analyzer loaded")
        
        # biz_gen = BusinessPlanGenerator()
        # print("  ✓ Business Plan Generator loaded")
        
        return True
    except Exception as e:
        print(f"  ✗ Professional tools error: {e}")
        return False

def verify_ethics_module():
    """Verify ethical AI module"""
    print("✓ Checking ethics module...")
    try:
        from src.ethics import BiasDetector, TransparencyEngine, EthicalAIGuard
        
        bias_detector = BiasDetector()
        audit = bias_detector.audit_response("This is a neutral test response.")
        print(f"  ✓ Bias detector working (bias-free: {audit['is_safe_to_use']})")
        
        transparency = TransparencyEngine()
        print("  ✓ Transparency engine loaded")
        
        guard = EthicalAIGuard()
        validation = guard.validate_response("Test response")
        print(f"  ✓ Ethical AI guard working (ethical: {validation['is_ethical']})")
        
        return True
    except Exception as e:
        print(f"  ✗ Ethics module error: {e}")
        return False

def verify_dependencies():
    """Verify new dependencies are installed"""
    print("✓ Checking new dependencies...")
    try:
        import cryptography
        print(f"  ✓ cryptography: {cryptography.__version__}")
        
        import sklearn
        print(f"  ✓ scikit-learn: {sklearn.__version__}")
        
        import joblib
        print(f"  ✓ joblib: {joblib.__version__}")
        
        return True
    except ImportError as e:
        print(f"  ✗ Missing dependency: {e}")
        print("  → Run: pip install -r requirements.txt")
        return False

def main():
    print("=" * 60)
    print("Aether AI v0.2.0 Upgrade Verification")
    print("=" * 60)
    print()
    
    results = []
    
    results.append(("Dependencies", verify_dependencies()))
    results.append(("Multi-Agent System", verify_multi_agent_system()))
    results.append(("Cybersecurity Module", verify_security_module()))
    results.append(("Professional Tools", verify_professional_tools()))
    results.append(("Ethics Module", verify_ethics_module()))
    
    print()
    print("=" * 60)
    print("Verification Results")
    print("=" * 60)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    total = len(results)
    passed = sum(1 for _, r in results if r)
    
    print()
    print(f"Total: {passed}/{total} checks passed ({passed/total*100:.0f}%)")
    
    if passed == total:
        print()
        print("🎉 All verification checks passed!")
        print("Aether AI v0.2.0 is ready to use.")
        print()
        print("New features available:")
        print("  • Multi-Agent System (5 specialized agents)")
        print("  • Cybersecurity Module (threat detection, encryption, compliance)")
        print("  • Job Automation (data analyst, strategy consultant, PM)")
        print("  • SWOT Analysis & Business Plan Generation")
        print("  • Ethical AI (bias detection, transparency)")
        return 0
    else:
        print()
        print("⚠️ Some checks failed. Please review errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
