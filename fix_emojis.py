import re
import glob
from pathlib import Path

def remove_emojis_from_logger(file_path):
    """Remove emojis from logger.info statements"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    
    # Pattern to match logger.info with emojis at start
    # Matches things like: logger.info("🔥 Some message")
    pattern = r'(logger\.(?:info|debug|warning|error)\(["\'])([^\w\s]+\s+)([^"\']+)'
    
    def replace_emoji(match):
        prefix = match.group(1)
        emoji = match.group(2)
        message = match.group(3)
        # Remove emoji but keep the message
        return f'{prefix}{message}'
    
    content = re.sub(pattern, replace_emoji, content)
    
    if content != original:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

# Fix all Python files in src/
patterns = [
    'src/**/*.py'
]

fixed = []
for pattern in patterns:
    for file in glob.glob(pattern, recursive=True):
        if remove_emojis_from_logger(file):
            fixed.append(file)
            print(f"Fixed: {file}")

print(f"\nTotal files fixed: {len(fixed)}")
