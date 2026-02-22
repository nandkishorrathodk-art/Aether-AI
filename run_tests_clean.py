import subprocess

def run():
    print("Running pytest...")
    with open("test_report_clean.txt", "w", encoding="utf-8") as f:
        subprocess.run(
            [r"venv\Scripts\python.exe", "-m", "pytest", "tests/unit/", "-v", "--lf"],
            stdout=f,
            stderr=subprocess.STDOUT,
            encoding="utf-8"
        )
    print("Done writing to test_report_clean.txt")

if __name__ == "__main__":
    run()
