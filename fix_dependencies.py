import sys
import subprocess
import os
import pkg_resources

def install(package):
    print(f"🔧 Installing {package}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ {package} installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install {package}: {e}")

required = {
    'openai-whisper': 'whisper', 
    'pvporcupine': 'pvporcupine', 
    'webrtcvad-wheels': 'webrtcvad',
    'requests': 'requests',
    'numpy': 'numpy'
}

# Check and install dependencies
print(f"Python Executable: {sys.executable}")
print("Checking core dependencies...")

installed = {pkg.key for pkg in pkg_resources.working_set}

for package, import_name in required.items():
    if package.lower() in installed:
        print(f"✅ {package} is already installed.")
    else:
        print(f"⚠️ {package} missing. Attempting install...")
        install(package)

print("Dependency check complete.")

# Write PYTHON_PATH to .env for the Node.js backend
env_path = ".env"
python_path = sys.executable.replace("\\", "/")
print(f"Writing PYTHON_PATH={python_path} to {env_path}")

try:
    # Read existing .env
    env_content = ""
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            env_content = f.read()
    
    # Update or append PYTHON_PATH
    new_lines = []
    found = False
    for line in env_content.splitlines():
        if line.startswith("PYTHON_PATH="):
            new_lines.append(f"PYTHON_PATH={python_path}")
            found = True
        else:
            new_lines.append(line)
    
    if not found:
        new_lines.append(f"PYTHON_PATH={python_path}")
    
    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines))
        
    print("✅ .env updated successfully")

except Exception as e:
    print(f"❌ Failed to update .env: {e}")
