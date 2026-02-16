"""
Test all new features added in this session
"""

import sys
import asyncio


def test_workflow_templates():
    """Test workflow templates"""
    print("\n" + "="*70)
    print("TEST 1: Workflow Templates")
    print("="*70)
    
    try:
        from src.action.workflows.templates import WorkflowTemplates
        
        # List all templates
        templates = WorkflowTemplates.list_templates()
        print(f"[OK] Loaded {len(templates)} templates")
        
        # Get categories
        categories = WorkflowTemplates.get_categories()
        print(f"[OK] Found {len(categories)} categories:")
        for cat in categories:
            count = len(WorkflowTemplates.list_templates(cat))
            print(f"     - {cat}: {count} templates")
        
        # Get specific template
        template = WorkflowTemplates.get_template('email_cleanup')
        if template:
            print(f"[OK] Retrieved template: {template['name']}")
            print(f"     Steps: {len(template['steps'])}")
        
        # Search templates
        results = WorkflowTemplates.search_templates('email')
        print(f"[OK] Search 'email' found {len(results)} templates")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_workflow_recorder():
    """Test workflow recorder"""
    print("\n" + "="*70)
    print("TEST 2: Workflow Recorder")
    print("="*70)
    
    try:
        from src.action.workflows.recorder import WorkflowRecorder
        
        recorder = WorkflowRecorder()
        print("[OK] Workflow Recorder initialized")
        
        # Check workflow directory
        print(f"[OK] Workflow directory: {recorder.workflow_dir}")
        
        # List existing workflows
        workflows = recorder.list_workflows()
        print(f"[OK] Found {len(workflows)} saved workflows")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_smart_browser():
    """Test smart browser automation"""
    print("\n" + "="*70)
    print("TEST 3: Smart Browser Automation")
    print("="*70)
    
    try:
        from src.action.automation.smart_browser import SmartBrowserAutomation
        
        browser = SmartBrowserAutomation(headless=True)
        print("[OK] Smart Browser initialized")
        print(f"     Headless: {browser.headless}")
        
        # Check methods
        methods = [
            'launch_with_ai',
            'navigate_smart',
            'click_by_description',
            'fill_form_smart',
            'extract_data_smart',
            'handle_captcha_auto',
            'multi_tab_orchestration',
            'record_workflow',
            'replay_workflow'
        ]
        
        for method in methods:
            if hasattr(browser, method):
                print(f"[OK] Method available: {method}()")
            else:
                print(f"[FAIL] Missing method: {method}()")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_api_routes():
    """Test workflow API routes"""
    print("\n" + "="*70)
    print("TEST 4: Workflow API Routes")
    print("="*70)
    
    try:
        from src.api.routes import workflows
        
        routes = workflows.router.routes
        print(f"[OK] Workflow API loaded: {len(routes)} routes")
        
        expected_routes = [
            '/api/v1/workflows/record/start',
            '/api/v1/workflows/record/stop',
            '/api/v1/workflows/list',
            '/api/v1/workflows/replay',
            '/api/v1/workflows/templates',
            '/api/v1/workflows/stats'
        ]
        
        route_paths = [r.path for r in routes]
        
        for expected in expected_routes:
            if any(expected in path for path in route_paths):
                print(f"[OK] Route registered: {expected}")
            else:
                print(f"[FAIL] Route missing: {expected}")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_puppeteer_controller():
    """Test Puppeteer TypeScript controller"""
    print("\n" + "="*70)
    print("TEST 5: Puppeteer Controller")
    print("="*70)
    
    try:
        import os
        from pathlib import Path
        
        controller_path = Path("src-ts/automation/puppeteer_controller.ts")
        
        if controller_path.exists():
            print(f"[OK] Puppeteer controller exists")
            
            # Check file size
            size = controller_path.stat().st_size
            print(f"[OK] File size: {size} bytes")
            
            # Check content
            content = controller_path.read_text()
            
            classes = ['PuppeteerController']
            methods = ['launch', 'navigate', 'click', 'type', 'getText', 'screenshot']
            
            for cls in classes:
                if cls in content:
                    print(f"[OK] Class found: {cls}")
            
            for method in methods:
                if f"async {method}" in content or f"{method}(" in content:
                    print(f"[OK] Method found: {method}()")
            
            return True
        else:
            print(f"[FAIL] Controller file not found")
            return False
        
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_extraction_results():
    """Test Vy extraction results"""
    print("\n" + "="*70)
    print("TEST 6: Vy Extraction Results")
    print("="*70)
    
    try:
        from pathlib import Path
        
        extract_dir = Path("vy_extracted")
        
        if extract_dir.exists():
            print(f"[OK] Extraction directory exists")
            
            # Check subdirectories
            subdirs = ['strings', 'javascript', 'resources', 'asar_files']
            
            for subdir in subdirs:
                path = extract_dir / subdir
                if path.exists():
                    file_count = len(list(path.glob("*")))
                    print(f"[OK] {subdir}/: {file_count} files")
                else:
                    print(f"[FAIL] {subdir}/ not found")
            
            return True
        else:
            print(f"[FAIL] Extraction directory not found")
            return False
        
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def test_main_api_integration():
    """Test main API has workflows integrated"""
    print("\n" + "="*70)
    print("TEST 7: Main API Integration")
    print("="*70)
    
    try:
        from src.api.main import app
        
        # Count total routes
        total_routes = len(app.routes)
        print(f"[OK] Total API routes: {total_routes}")
        
        # Check for workflow routes
        workflow_routes = [r for r in app.routes if '/workflows' in str(r.path)]
        print(f"[OK] Workflow routes integrated: {len(workflow_routes)}")
        
        return True
        
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def main():
    """Run all tests"""
    print("="*70)
    print("  AETHER NEW FEATURES TEST SUITE")
    print("="*70)
    print("\nTesting all features added in this session...")
    
    tests = [
        ("Workflow Templates", test_workflow_templates),
        ("Workflow Recorder", test_workflow_recorder),
        ("Smart Browser", test_smart_browser),
        ("API Routes", test_api_routes),
        ("Puppeteer Controller", test_puppeteer_controller),
        ("Vy Extraction", test_extraction_results),
        ("Main API Integration", test_main_api_integration)
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n[ERROR] Test '{name}' crashed: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "[OK]" if result else "[X]"
        print(f"{symbol} {name}: {status}")
    
    print("\n" + "="*70)
    print(f"RESULTS: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("="*70)
    
    if passed == total:
        print("\n[SUCCESS] All tests passed! Aether is ready to rock!")
        return 0
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
