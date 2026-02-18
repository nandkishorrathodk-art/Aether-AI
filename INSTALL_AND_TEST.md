# 🚀 Aether AI v2.0 - Quick Installation & Testing

## ⚡ **Quick Start (5 Minutes)**

### **Step 1: Install Python Dependencies**

```powershell
# Navigate to project
cd C:\Users\nandk\.zenflow\worktrees\aether-00f9\aether-ai-repo

# Install all dependencies
pip install -r requirements.txt
```

### **Step 2: Install Tesseract OCR (Required for Vision System)**

Download and install Tesseract OCR:

**Option A: Download Installer**
1. Download from: https://github.com/UB-Mannheim/tesseract/wiki
2. Run installer (`tesseract-ocr-w64-setup-*.exe`)
3. Install to: `C:\Program Files\Tesseract-OCR\`
4. ✅ **Check "Add to PATH"** during installation

**Option B: Using Chocolatey**
```powershell
choco install tesseract
```

**Option C: Using Scoop**
```powershell
scoop install tesseract
```

**Verify Installation:**
```powershell
tesseract --version
```

Should output: `tesseract v5.x.x`

---

### **Step 3: Run Tests!** 🧪

#### **Option A: Run All Tests**
```powershell
python -m pytest tests/ -v
```

#### **Option B: Run Specific Test Suite**
```powershell
# Test autonomous system
python -m pytest tests/test_autonomous_system.py -v

# Test bug bounty enhancements
python -m pytest tests/test_bugbounty_enhancements.py -v
```

#### **Option C: Quick Single Test**
```powershell
python -m pytest tests/test_autonomous_system.py::TestAutonomousBrain::test_brain_initialization -v
```

#### **Option D: With Coverage**
```powershell
python -m pytest tests/ --cov=src --cov-report=html
# Open: htmlcov\index.html
```

---

## 🔧 **Troubleshooting**

### **Problem 1: `ModuleNotFoundError: No module named 'pytesseract'`**

**Solution:**
```powershell
pip install pytesseract
```

### **Problem 2: `TesseractNotFoundError`**

**Solution:**
Set Tesseract path manually:

Create `pytesseract_config.py`:
```python
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
```

Or add to PATH:
```powershell
$env:PATH += ";C:\Program Files\Tesseract-OCR"
```

### **Problem 3: `ImportError` in tests**

**Solution:**
```powershell
# Set PYTHONPATH
$env:PYTHONPATH = "C:\Users\nandk\.zenflow\worktrees\aether-00f9\aether-ai-repo"

# Then run tests
python -m pytest tests/ -v
```

### **Problem 4: Tests fail with LLM errors**

**Solution:**
Tests use mocks - no real LLM API needed!

If still failing, add to `.env`:
```env
OPENAI_API_KEY=test_key_for_testing
DEFAULT_PROVIDER=openai
```

---

## ✅ **Expected Test Results**

When all tests pass, you'll see:

```
=========================== test session starts ===========================
platform win32 -- Python 3.12.10, pytest-9.0.2
collected 32 items

tests/test_autonomous_system.py .........                           [28%]
tests/test_bugbounty_enhancements.py .......................        [100%]

========================= 32 passed in 25.43s ==========================
```

---

## 🚀 **Next Steps After Testing**

Once tests pass:

1. **Start Backend:**
   ```powershell
   python -m uvicorn src.api.main:app --reload
   ```

2. **Test Autonomous Mode:**
   ```powershell
   # In another terminal
   curl -X POST http://localhost:8000/api/v1/autonomous/simple-start `
     -H "Content-Type: application/json" `
     -d '{\"target\": \"example.com\"}'
   ```

3. **Check Status:**
   ```powershell
   curl http://localhost:8000/api/v1/autonomous/status
   ```

---

## 📞 **Still Having Issues?**

1. **Check Python version:**
   ```powershell
   python --version  # Should be 3.11+ or 3.12+
   ```

2. **Reinstall dependencies:**
   ```powershell
   pip uninstall -r requirements.txt -y
   pip install -r requirements.txt
   ```

3. **Clear pytest cache:**
   ```powershell
   rmdir /s /q .pytest_cache
   rmdir /s /q __pycache__
   ```

4. **Check logs:**
   ```powershell
   type logs\test.log
   ```

---

## 🎯 **Quick Command Reference**

```powershell
# Full test suite
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=src --cov-report=html

# Specific test
python -m pytest tests/test_autonomous_system.py::TestClassName::test_name -v

# Stop on first failure
python -m pytest tests/ -x

# Show print output
python -m pytest tests/ -s

# Parallel execution (faster)
pip install pytest-xdist
python -m pytest tests/ -n auto
```

---

**Ready? Run this now:**

```powershell
cd C:\Users\nandk\.zenflow\worktrees\aether-ai-repo
pip install -r requirements.txt
python -m pytest tests/test_autonomous_system.py -v
```

🔥 **Let's go boss!** 🔥
