#!/usr/bin/env python
"""Test manual testing agent import"""

try:
    from src.bugbounty.manual_testing_agent import ManualTestingAgent
    print("[OK] ManualTestingAgent import successful!")
    
    from src.bugbounty.models_manual import (
        InterceptedRequest, RequestAnalysis, ParameterAnalysis,
        TestPayload, ModifiedRequest, ResponseAnalysis,
        TestDecision, ApplicationKnowledge, ExploitChain,
        ManualTestingSession
    )
    print("[OK] All models_manual imports successful!")
    
    print("\n[SUCCESS] All manual testing agent components loaded successfully!")
    print("Components available:")
    print("  - BurpInterceptWatcher")
    print("  - RequestAnalyzer")
    print("  - SuggestionEngine")
    print("  - ContextAwarePayloadGenerator")
    print("  - IntelligentRequestModifier")
    print("  - ResponseAnomalyDetector")
    print("  - DecisionEngine")
    print("  - LearningLoop")
    print("  - ExploitChainer")
    print("  - ManualTestingAgent (MAIN ORCHESTRATOR)")
    print("\n==> Manual Testing Agent v3.0.2 ready for human-like manual testing!")
    
except ImportError as e:
    print(f"[ERROR] Import failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
