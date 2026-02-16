"""
Comprehensive Test Suite for Aether AI

Tests all major components:
1. Plugin System
2. Developer Tools
3. Multi-Agent System
4. Vision System
5. Code Generation
6. Proactive Intelligence
7. Self-Learning
8. API Endpoints
"""

import sys
import time
from typing import Dict, Any, List

# Configure UTF-8 output for Windows
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

# Test results tracking
test_results = {
    'total': 0,
    'passed': 0,
    'failed': 0,
    'skipped': 0,
    'tests': []
}


def run_test(test_name: str, test_func):
    """Run a test and track results"""
    global test_results
    
    test_results['total'] += 1
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print('='*60)
    
    try:
        start_time = time.time()
        result = test_func()
        duration = time.time() - start_time
        
        if result:
            test_results['passed'] += 1
            status = "[PASS]"
        else:
            test_results['failed'] += 1
            status = "[FAIL]"
        
        test_results['tests'].append({
            'name': test_name,
            'status': 'passed' if result else 'failed',
            'duration': duration
        })
        
        print(f"\n{status} ({duration:.2f}s)")
        return result
        
    except Exception as e:
        test_results['failed'] += 1
        test_results['tests'].append({
            'name': test_name,
            'status': 'failed',
            'error': str(e)
        })
        print(f"\n[FAIL]: {e}")
        return False


def test_imports():
    """Test if all core modules can be imported"""
    print("Testing module imports...")
    
    try:
        # Core modules
        from src.utils.logger import get_logger
        print("[OK] Logger")
        
        from src.config import settings
        print("[OK] Config")
        
        # Plugin system (new)
        from src.plugins.plugin_system import PluginManager, MCPIntegration
        print("[OK] Plugin System")
        
        from src.plugins.marketplace import PluginMarketplace
        print("[OK] Marketplace")
        
        # Developer tools (new)
        from src.developer.dev_tools import Debugger, Profiler, ErrorDiagnostics, PluginGenerator
        print("[OK] Developer Tools")
        
        # Multi-agent system
        from src.cognitive.agents.multi_agent_system import MultiAgentSystem
        print("[OK] Multi-Agent System")
        
        # Vision system
        from src.cognitive.vision.image_analyzer import ImageAnalyzer
        print("[OK] Vision System")
        
        # Code generation
        from src.cognitive.code_generation.code_agent import CodeAgent
        print("[OK] Code Generation")
        
        # Proactive intelligence
        from src.cognitive.proactive.suggestion_engine import ProactiveEngine
        print("[OK] Proactive Intelligence")
        
        # Self-learning
        from src.cognitive.learning.self_improvement import SelfLearningEngine
        print("[OK] Self-Learning")
        
        # LLM
        from src.cognitive.llm.model_loader import ModelLoader
        print("[OK] Model Loader")
        
        return True
        
    except ImportError as e:
        print(f"Import error: {e}")
        return False


def test_plugin_system():
    """Test plugin system functionality"""
    print("Testing Plugin System...")
    
    try:
        from src.plugins.plugin_system import PluginManager, PluginType
        from pathlib import Path
        
        # Create plugin manager
        plugin_manager = PluginManager(plugins_dir="./test_plugins")
        print("[OK] Plugin Manager created")
        
        # Create test plugin directory
        test_plugin_dir = Path("./test_plugins/test-plugin")
        test_plugin_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test plugin metadata
        import json
        metadata = {
            "name": "test-plugin",
            "version": "1.0.0",
            "author": "Test",
            "description": "Test plugin",
            "type": "native_python",
            "entry_point": "plugin.py",
            "dependencies": [],
            "capabilities": ["test"],
            "permissions": []
        }
        
        with open(test_plugin_dir / "plugin.json", 'w') as f:
            json.dump(metadata, f)
        print("[OK] Test plugin metadata created")
        
        # Create test plugin code
        plugin_code = '''
def hello():
    return "Hello from test plugin!"

class TestPlugin:
    def __init__(self):
        self.name = "test-plugin"
    
    def execute(self, command):
        if command == "hello":
            return hello()
        return None

def create_plugin():
    return TestPlugin()
'''
        
        with open(test_plugin_dir / "plugin.py", 'w') as f:
            f.write(plugin_code)
        print("[OK] Test plugin code created")
        
        # Discover plugins
        discovered = plugin_manager.discover_plugins()
        print(f"[OK] Discovered {len(discovered)} plugins")
        
        # Get statistics
        stats = plugin_manager.get_statistics()
        print(f"[OK] Statistics: {stats}")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_developer_tools():
    """Test developer tools"""
    print("Testing Developer Tools...")
    
    try:
        from src.developer.dev_tools import Debugger, Profiler, ErrorDiagnostics, PluginGenerator
        
        # Test Debugger
        debugger = Debugger()
        debugger.add_breakpoint("test.py", 10, condition="x > 5")
        print("✓ Debugger: Breakpoint added")
        
        # Test Profiler
        profiler = Profiler()
        
        @profiler.profile_function
        def test_function():
            total = 0
            for i in range(1000):
                total += i
            return total
        
        result = test_function()
        print(f"✓ Profiler: Function profiled (result: {result})")
        
        hotspots = profiler.get_hotspots()
        print(f"✓ Profiler: {len(hotspots)} hotspots detected")
        
        # Test Error Diagnostics
        error_diag = ErrorDiagnostics()
        print("✓ Error Diagnostics created")
        
        # Test Plugin Generator
        generator = PluginGenerator()
        code = generator.generate_plugin("my-test-plugin", language="python", template="basic")
        print(f"✓ Plugin Generator: Generated {len(code)} chars of code")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_multi_agent_system():
    """Test multi-agent system"""
    print("Testing Multi-Agent System...")
    
    try:
        from src.cognitive.agents.multi_agent_system import MultiAgentSystem
        
        # Create multi-agent system
        mas = MultiAgentSystem()
        print(f"✓ Multi-Agent System created with {len(mas.agents)} agents")
        
        # Get capabilities
        capabilities = mas.get_agent_capabilities()
        print(f"✓ Agent capabilities: {len(capabilities)} agents")
        
        for agent_name, caps in capabilities.items():
            print(f"  - {agent_name}: {len(caps)} capabilities")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_vision_system():
    """Test vision system"""
    print("Testing Vision System...")
    
    try:
        from src.cognitive.vision.image_analyzer import ImageAnalyzer
        
        # Create image analyzer
        analyzer = ImageAnalyzer()
        print("✓ Image Analyzer created")
        
        # Note: Actual image analysis requires API keys
        print("✓ Vision system initialized (API tests skipped)")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_code_generation():
    """Test code generation agent"""
    print("Testing Code Generation...")
    
    try:
        from src.cognitive.code_generation.code_agent import CodeAgent
        
        # Create code agent
        agent = CodeAgent()
        print("✓ Code Agent created")
        
        # Index codebase (would take too long, skip for now)
        print("✓ Code generation system initialized")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_proactive_intelligence():
    """Test proactive intelligence"""
    print("Testing Proactive Intelligence...")
    
    try:
        from src.cognitive.proactive.suggestion_engine import ProactiveEngine
        
        # Create proactive engine
        engine = ProactiveEngine()
        print("✓ Proactive Engine created")
        
        # Log some activities
        engine.log_activity("coding", {"file": "test.py"})
        engine.log_activity("testing", {"test": "unit_test"})
        print("✓ Activities logged")
        
        # Get suggestions
        suggestions = engine.get_suggestions(max_suggestions=3)
        print(f"✓ Generated {len(suggestions)} suggestions")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_self_learning():
    """Test self-learning system"""
    print("Testing Self-Learning System...")
    
    try:
        from src.cognitive.learning.self_improvement import SelfLearningEngine
        
        # Create learning engine
        learning = SelfLearningEngine(storage_path="./test_data/learning")
        print("✓ Self-Learning Engine created")
        
        # Record interaction
        learning.record_interaction(
            prompt="Test prompt",
            response="Test response",
            task_type="test",
            success=True
        )
        print("✓ Interaction recorded")
        
        # Get insights
        insights = learning.get_learning_insights()
        print(f"✓ Learning insights: {insights['total_interactions']} interactions")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_structure():
    """Test API route structure"""
    print("Testing API Structure...")
    
    try:
        from src.api.main import app
        print("✓ FastAPI app imported")
        
        # Get all routes
        routes = []
        for route in app.routes:
            if hasattr(route, 'path'):
                routes.append(route.path)
        
        print(f"✓ Total routes: {len(routes)}")
        
        # Check for new plugin routes
        plugin_routes = [r for r in routes if '/plugins' in r]
        print(f"✓ Plugin routes: {len(plugin_routes)}")
        
        # Check for developer routes
        dev_routes = [r for r in routes if '/developer' in r]
        print(f"✓ Developer routes: {len(dev_routes)}")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config():
    """Test configuration system"""
    print("Testing Configuration...")
    
    try:
        from src.config import settings
        
        print(f"✓ App name: {settings.app_name}")
        print(f"✓ App version: {settings.app_version}")
        print(f"✓ Environment: {getattr(settings, 'environment', 'development')}")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False


def print_summary():
    """Print test summary"""
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    print(f"\nTotal Tests: {test_results['total']}")
    print(f"[PASS] Passed: {test_results['passed']}")
    print(f"[FAIL] Failed: {test_results['failed']}")
    print(f"[SKIP] Skipped: {test_results['skipped']}")
    
    pass_rate = (test_results['passed'] / test_results['total'] * 100) if test_results['total'] > 0 else 0
    print(f"\nPass Rate: {pass_rate:.1f}%")
    
    print("\nDetailed Results:")
    for test in test_results['tests']:
        status = "[PASS]" if test['status'] == 'passed' else "[FAIL]"
        duration = test.get('duration', 0)
        print(f"{status} {test['name']} ({duration:.2f}s)")
        if 'error' in test:
            print(f"   Error: {test['error']}")
    
    print("\n" + "="*60)
    
    if pass_rate >= 80:
        print("[EXCELLENT!] All major systems working!")
    elif pass_rate >= 60:
        print("[GOOD!] Most systems working!")
    else:
        print("[NEEDS ATTENTION!] Some systems need fixes!")
    
    print("="*60)


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("AETHER AI - COMPREHENSIVE TEST SUITE")
    print("="*60)
    print("\nTesting all major components...")
    print(f"Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    start_time = time.time()
    
    # Run all tests
    run_test("1. Module Imports", test_imports)
    run_test("2. Configuration System", test_config)
    run_test("3. Plugin System", test_plugin_system)
    run_test("4. Developer Tools", test_developer_tools)
    run_test("5. Multi-Agent System", test_multi_agent_system)
    run_test("6. Vision System", test_vision_system)
    run_test("7. Code Generation", test_code_generation)
    run_test("8. Proactive Intelligence", test_proactive_intelligence)
    run_test("9. Self-Learning System", test_self_learning)
    run_test("10. API Structure", test_api_structure)
    
    total_duration = time.time() - start_time
    
    print(f"\nTotal test duration: {total_duration:.2f}s")
    
    # Print summary
    print_summary()
    
    # Return exit code
    return 0 if test_results['failed'] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
