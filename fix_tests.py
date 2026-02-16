import re

with open('tests/integration/test_api.py', 'r') as f:
    content = f.read()

content = re.sub(r'def (test_\w+)\(self\):', r'def \1(self, client):', content)

with open('tests/integration/test_api.py', 'w') as f:
    f.write(content)

print("Test file updated successfully")
