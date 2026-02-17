import os
import shutil
from datetime import datetime
from pathlib import Path


class AetherMigrationV090:
    def __init__(self):
        self.root_dir = Path(__file__).parent.parent
        self.env_file = self.root_dir / ".env"
        self.env_example = self.root_dir / ".env.example"
        self.backup_dir = self.root_dir / "backups"
        
    def backup_env(self):
        if not self.env_file.exists():
            print("[INFO] No .env file found. Skipping backup.")
            return None
            
        self.backup_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f".env.backup_{timestamp}"
        
        shutil.copy2(self.env_file, backup_path)
        print(f"[OK] Backed up .env to {backup_path}")
        return backup_path
    
    def get_new_v090_settings(self):
        return {
            # Screen Monitoring
            "ENABLE_SCREEN_MONITORING": "false",
            "SCREEN_CAPTURE_INTERVAL": "30",
            "SCREEN_MONITOR_SAVE_SCREENSHOTS": "false",
            "SCREEN_MONITOR_DATA_PATH": "./data/monitoring",
            
            # Proactive AI
            "ENABLE_PROACTIVE_MODE": "true",
            "PROACTIVE_CHECK_INTERVAL": "1800",
            "PROACTIVE_MORNING_GREETING": "true",
            "PROACTIVE_DAILY_PLANNING": "true",
            "PROACTIVE_SUGGESTION_TYPES": "bug_bounty,youtube,breaks,learning",
            
            # PC Control
            "ENABLE_PC_CONTROL": "false",
            "PC_CONTROL_REQUIRE_CONFIRMATION": "true",
            "PC_CONTROL_ALLOWED_ACTIONS": "mouse_click,keyboard_type,app_launch",
            "PC_CONTROL_AUDIT_LOG": "./data/control_audit.log",
            
            # Bug Bounty Autopilot
            "ENABLE_BUGBOUNTY_AUTOPILOT": "false",
            "BURPSUITE_API_URL": "http://127.0.0.1:1337",
            "BURPSUITE_API_KEY": "your-burp-api-key-here",
            "BUGBOUNTY_AUTO_SCAN": "false",
            "BUGBOUNTY_TARGET_PROGRAMS": "apple,google,microsoft",
            "BUGBOUNTY_REPORT_PATH": "./data/bugbounty_reports",
            
            # Personality & Language
            "PERSONALITY_MODE": "friendly",
            "PERSONALITY_ENABLE_HINDI_ENGLISH": "true",
            "PERSONALITY_EMOJI_ENABLED": "true",
            "PERSONALITY_MOTIVATIONAL_ENABLED": "true",
            "PERSONALITY_HUMOR_ENABLED": "true",
            
            # Daily Intelligence
            "ENABLE_DAILY_REPORTS": "true",
            "DAILY_REPORT_TIME": "20:00",
            "DAILY_REPORT_PATH": "./data/daily_reports",
            "ENABLE_TREND_ANALYSIS": "true",
            "ENABLE_WEALTH_TRACKING": "true",
        }
    
    def read_env_file(self):
        if not self.env_file.exists():
            return {}
        
        env_vars = {}
        with open(self.env_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
        
        return env_vars
    
    def write_env_file(self, env_vars):
        if not self.env_file.exists() and self.env_example.exists():
            shutil.copy2(self.env_example, self.env_file)
            print("[OK] Created .env from .env.example")
        
        existing_content = []
        if self.env_file.exists():
            with open(self.env_file, 'r', encoding='utf-8') as f:
                existing_content = f.readlines()
        
        with open(self.env_file, 'a', encoding='utf-8') as f:
            if existing_content and not existing_content[-1].endswith('\n'):
                f.write('\n')
            
            f.write('\n# v0.9.0 Migration - Added Settings\n')
            
            for key, value in env_vars.items():
                f.write(f'{key}={value}\n')
        
        print(f"[OK] Added {len(env_vars)} new settings to .env")
    
    def update_app_version(self):
        existing_vars = self.read_env_file()
        if 'APP_VERSION' in existing_vars:
            content = self.env_file.read_text(encoding='utf-8')
            content = content.replace(
                f"APP_VERSION={existing_vars['APP_VERSION']}", 
                "APP_VERSION=0.9.0"
            )
            self.env_file.write_text(content, encoding='utf-8')
            print("[OK] Updated APP_VERSION to 0.9.0")
    
    def create_directories(self):
        directories = [
            self.root_dir / "data" / "monitoring",
            self.root_dir / "data" / "bugbounty_reports",
            self.root_dir / "data" / "daily_reports",
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"[OK] Created directory: {directory.relative_to(self.root_dir)}")
    
    def migrate(self):
        print("[MIGRATION] Starting Aether AI v0.9.0 Migration")
        print("=" * 60)
        
        backup_path = self.backup_env()
        
        existing_vars = self.read_env_file()
        new_settings = self.get_new_v090_settings()
        
        settings_to_add = {}
        for key, value in new_settings.items():
            if key not in existing_vars:
                settings_to_add[key] = value
        
        if settings_to_add:
            self.write_env_file(settings_to_add)
        else:
            print("[INFO] All v0.9.0 settings already present in .env")
        
        self.update_app_version()
        
        self.create_directories()
        
        print("=" * 60)
        print("[SUCCESS] Migration to v0.9.0 completed successfully!")
        print("\n[NEXT STEPS]")
        print("1. Review your .env file and update any settings as needed")
        print("2. Install new dependencies: pip install -r requirements.txt")
        print("3. Restart Aether AI to use new features")
        
        if backup_path:
            print(f"\n[BACKUP] Backup location: {backup_path}")


def main():
    migration = AetherMigrationV090()
    migration.migrate()


if __name__ == "__main__":
    main()
