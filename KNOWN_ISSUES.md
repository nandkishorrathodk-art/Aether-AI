# Known Issues - Aether AI MVP v0.1.0

This document tracks bugs, limitations, and issues identified during testing of the MVP release.

## Critical Issues

### 1. Integration Test API Client Compatibility
**Severity**: High  
**Component**: tests/integration/test_api.py  
**Description**: TestClient initialization fails with `TypeError: Client.__init__() got an unexpected keyword argument 'app'`  
**Impact**: Integration tests for API endpoints cannot run  
**Root Cause**: Version incompatibility between Starlette and httpx libraries  
**Workaround**: None currently  
**Fix Required**: Update TestClient usage to match current Starlette/httpx API

### 2. Integration Tests Timeout
**Severity**: High  
**Component**: tests/integration/  
**Description**: Integration tests timeout after 2 minutes when running conversation and voice pipeline tests  
**Impact**: Cannot verify end-to-end integration automatically  
**Root Cause**: Long-running tests with actual AI provider API calls  
**Workaround**: Run tests individually with longer timeout  
**Fix Required**: Add mocking for external API calls in integration tests

## High Priority Issues

### 3. AsyncClient Proxies Parameter Error
**Severity**: Medium  
**Component**: src/cognitive/llm/providers/  
**Description**: Provider initialization fails with `AsyncClient.__init__() got an unexpected keyword argument 'proxies'`  
**Affected Providers**: OpenAI, Anthropic, OpenRouter  
**Impact**: These providers fail to initialize if proxy configuration attempted  
**Root Cause**: Updated library versions removed 'proxies' parameter  
**Workaround**: Don't configure proxies  
**Fix Required**: Update provider initialization to use current API

### 4. Code Coverage Below Target
**Severity**: Medium  
**Component**: Overall codebase  
**Description**: Code coverage is 43% (target: 80%)  
**Uncovered Modules**:
- src/api/main.py: 0%
- src/api/routes/*.py: 0%
- src/api/middleware/rate_limiter.py: 0%
- src/pipeline/voice_pipeline.py: 0%
- src/main.py: 0%
**Impact**: Large portions of code untested  
**Fix Required**: Add integration tests for API routes and pipeline

## Medium Priority Issues

### 5. Linting Issues (928 total)
**Severity**: Low-Medium  
**Component**: Overall codebase  
**Description**: Flake8 found 928 code style issues  
**Breakdown**:
- 843 W293: Blank lines with whitespace
- 34 E501: Lines too long (>100 characters)
- 39 F401: Unused imports
- 3 E402: Module imports not at top
- 2 E722: Bare except clauses
- 2 F541: f-strings missing placeholders
- 2 F811: Redefinition of unused imports
- 1 E302: Expected 2 blank lines
- 1 F841: Unused local variable
- 1 W291: Trailing whitespace
**Impact**: Code readability and maintainability  
**Fix Required**: Run automated formatter (black) and fix remaining issues

### 6. Unit Test Failures (11 failed)
**Severity**: Medium  
**Component**: tests/unit/  
**Failed Tests**:
- test_audio_utils.py: 2 failures (audio_to_bytes, energy_threshold_detection)
- test_memory.py: 5 failures (VectorStore operations - require sentence-transformers)
- test_wake_word.py: 4 failures (energy-based detection edge cases)
**Impact**: Some edge cases not handled correctly  
**Fix Required**: Investigate and fix root causes

### 7. Deprecated API Warnings
**Severity**: Low-Medium  
**Component**: Multiple  
**Description**: Several deprecation warnings during tests  
**Examples**:
- `on_event` deprecated in FastAPI (use lifespan handlers)
- `pkg_resources` deprecated in setuptools
- `resume_download` deprecated in huggingface_hub
- PyType_Spec metaclass warnings in protobuf
**Impact**: Future compatibility issues  
**Fix Required**: Update to recommended APIs before deprecations removed

## Low Priority Issues

### 8. Pytest Unknown Mark Warnings
**Severity**: Low  
**Component**: tests/integration/test_voice_pipeline.py  
**Description**: pytest.mark.integration not registered, causing warnings  
**Impact**: Cosmetic warnings in test output  
**Fix Required**: Register custom marks in pytest.ini or conftest.py

### 9. Missing Type Annotations
**Severity**: Low  
**Component**: Multiple modules  
**Description**: Many functions lack type hints  
**Impact**: Reduced IDE autocomplete and type checking effectiveness  
**Fix Required**: Add comprehensive type annotations

### 10. Unused Imports and Variables
**Severity**: Low  
**Component**: Multiple files  
**Description**: 39 unused imports, 1 unused variable  
**Impact**: Code bloat, confusion  
**Fix Required**: Remove unused imports and variables

## Limitations (Not Bugs)

### L1. Cloud-Only AI for MVP
**Description**: MVP relies on cloud API providers (OpenAI, Anthropic, etc.) instead of local models  
**Impact**: Requires internet connection and API keys for full functionality  
**Planned**: Phase 2 will add local LLM support (Llama, Mistral)

### L2. Windows-Only Testing
**Description**: Application primarily tested on Windows 10/11  
**Impact**: macOS and Linux compatibility unknown  
**Planned**: Cross-platform testing in future releases

### L3. English-Primary Voice Recognition
**Description**: Voice pipeline optimized for English, limited multilingual testing  
**Impact**: Non-English languages may have lower accuracy  
**Planned**: Expanded language support in Phase 2

### L4. Single User Profile
**Description**: ProfileManager supports multiple users, but UI only handles single user  
**Impact**: Multi-user workflows not fully tested  
**Planned**: Multi-user UI in future releases

### L5. Basic Automation Capabilities
**Description**: Automation engine has basic commands, not full workflow orchestration  
**Impact**: Complex multi-step automations require manual scripting  
**Planned**: Advanced automation workflows in Phase 3

## Performance Issues

### P1. Slow Initialization
**Description**: Voice pipeline initialization takes 15-20 seconds  
**Target**: <15 seconds  
**Impact**: Delayed startup for voice features  
**Optimization Needed**: Lazy loading, parallel initialization

### P2. Memory Usage for Embeddings
**Description**: sentence-transformers model uses ~500MB RAM  
**Impact**: Higher baseline memory usage  
**Optimization Needed**: Use lighter embedding models or lazy loading

### P3. API Latency for Cloud Providers
**Description**: Cloud API calls add 500-2000ms latency per request  
**Impact**: Response times >3s for complex queries  
**Optimization Needed**: Caching, provider selection optimization

## Security Concerns

### S1. API Keys in .env File
**Description**: API keys stored in plaintext .env file  
**Severity**: Medium  
**Impact**: Keys accessible if system compromised  
**Recommendation**: Add encryption for sensitive config values

### S2. No User Authentication
**Description**: API endpoints have no authentication  
**Severity**: Medium  
**Impact**: Anyone with network access can use API  
**Recommendation**: Add JWT or session-based auth in production

### S3. Path Traversal Risk in File Operations
**Description**: SafeFileOperations blocks dangerous paths but may have edge cases  
**Severity**: Low-Medium  
**Impact**: Potential access to unauthorized files  
**Recommendation**: Security audit of path validation logic

## Documentation Gaps

### D1. Missing API Authentication Guide
**Description**: No documentation on securing API endpoints  
**Impact**: Users may deploy insecure instances  
**Fix Required**: Add security best practices guide

### D2. Limited Troubleshooting for Voice Pipeline
**Description**: VOICE_PIPELINE.md has basic troubleshooting, needs expansion  
**Impact**: Users may struggle with audio device issues  
**Fix Required**: Expand troubleshooting section with common audio issues

### D3. No Architecture Diagram
**Description**: System architecture not visualized  
**Impact**: Harder for developers to understand component relationships  
**Fix Required**: Add architecture diagrams to documentation

## Test Coverage Gaps

### TC1. No UI Tests Running
**Description**: Playwright tests created but not executed in CI/testing  
**Impact**: UI functionality not validated automatically  
**Fix Required**: Run UI tests as part of testing workflow

### TC2. No Performance Benchmarks
**Description**: No automated performance tests tracking latency/resource usage  
**Impact**: Performance regressions may go unnoticed  
**Fix Required**: Add performance test suite with benchmarks

### TC3. No Load Testing
**Description**: API endpoints not tested under concurrent load  
**Impact**: Unknown behavior under stress  
**Fix Required**: Add load testing with tools like locust or k6

## Recommendations for v0.2.0

### High Priority
1. Fix integration test compatibility issues
2. Increase code coverage to 80%+
3. Fix unit test failures in memory and wake word modules
4. Update deprecated APIs (FastAPI on_event, etc.)
5. Add API authentication

### Medium Priority
6. Run automated code formatter (black)
7. Add comprehensive type annotations
8. Optimize initialization time
9. Add security audit for file operations
10. Expand troubleshooting documentation

### Low Priority
11. Register pytest custom marks
12. Remove unused imports and variables
13. Add architecture diagrams
14. Set up performance benchmarking
15. Implement UI automated testing in CI

---

**Last Updated**: 2026-02-08  
**Version**: MVP v0.1.0  
**Maintainer**: Aether AI Development Team
