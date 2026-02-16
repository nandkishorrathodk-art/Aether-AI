import subprocess
import sys
import os

def build_rust():
    print("🚀 Building Aether Rust Extension...")
    try:
        # Check if maturin is installed
        subprocess.run(["maturin", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("📦 Installing maturin...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "maturin"])

    # Build the extension
    cwd = os.path.dirname(os.path.abspath(__file__))
    try:
        subprocess.check_call(["maturin", "develop", "--release"], cwd=cwd)
        print("✅ Rust extension built and installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    build_rust()
