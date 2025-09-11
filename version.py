import re

with open("app.py", "r", encoding="utf-8") as f:
    content = f.read()

match = re.search(r'APP_VERSION\s*=\s*["\'](.+?)["\']', content)
if match:
    print(match.group(1))
else:
    print("0.0.0")  # fallback
# Extracts the APP_VERSION from app.py and prints it.