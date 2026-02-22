import sys
import os

file_path = r"c:\Users\nandk\Aether-AI\src\cognitive\llm\prompt_engine.py"
with open(file_path, "r", encoding="utf-8") as f:
    lines = f.readlines()

out = []
in_dict = False
for i, line in enumerate(lines):
    if "def _load_system_prompts" in line:
        out.append(line)
        out.append('        """Load system prompts from external markdown files"""\n')
        out.append('        import os\n')
        out.append('        prompts = {}\n')
        out.append('        prompt_dir = os.path.join(os.path.dirname(__file__), "prompts")\n')
        out.append('        if not os.path.exists(prompt_dir):\n')
        out.append('            os.makedirs(prompt_dir, exist_ok=True)\n')
        out.append('            return {"default": "You are Aether, a J.A.R.V.I.S.-class AI assistant."}\n')
        out.append('        try:\n')
        out.append('            for filename in os.listdir(prompt_dir):\n')
        out.append('                if filename.endswith(".md"):\n')
        out.append('                    name = filename[:-3]\n')
        out.append('                    with open(os.path.join(prompt_dir, filename), "r", encoding="utf-8") as pf:\n')
        out.append('                        prompts[name] = pf.read().strip()\n')
        out.append('            if "default" not in prompts:\n')
        out.append('                prompts["default"] = "You are Aether, a J.A.R.V.I.S.-class AI assistant."\n')
        out.append('            return prompts\n')
        out.append('        except Exception as e:\n')
        out.append('            logger.error(f"Failed to load system prompts: {e}")\n')
        out.append('            return {"default": "You are Aether, a J.A.R.V.I.S.-class AI assistant."}\n')
        in_dict = True
    elif in_dict and "def _load_few_shot_examples" in line:
        in_dict = False
        out.append("\n")
        out.append("    " + line.lstrip())
    elif not in_dict:
        out.append(line)

with open(file_path, "w", encoding="utf-8") as f:
    f.writelines(out)

print("Patched prompt_engine.py successfully.")
