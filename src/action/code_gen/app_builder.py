"""
Full Code Generation from Natural Language
AI-Powered Complete Application Builder
"""
from typing import Dict, List, Optional, Any
from pathlib import Path
import json
import re
from datetime import datetime


class AdvancedCodeGenerator:
    """
    AI-powered code generation from natural language
    
    Features:
    - Multi-language app generation (Python, React, Node.js, FastAPI, Flask, etc.)
    - Complete project scaffolding with best practices
    - Auto-generated tests, docs, deployment configs
    - Code analysis and refactoring
    - Bug fixing assistance
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize AdvancedCodeGenerator
        
        Args:
            llm_provider: LLM provider for AI-powered code generation
        """
        self.llm = llm_provider
        
        self.templates = {
            'react': {
                'files': ['package.json', 'src/App.js', 'src/index.js', 'README.md', 'src/App.css'],
                'structure': ['src', 'public', 'tests', 'src/components', 'src/utils']
            },
            'python': {
                'files': ['main.py', 'requirements.txt', 'README.md', 'tests/test_main.py', '.env.example'],
                'structure': ['src', 'tests', 'docs', 'scripts']
            },
            'fastapi': {
                'files': ['main.py', 'requirements.txt', 'README.md', 'Dockerfile', '.env.example'],
                'structure': ['app', 'app/api', 'app/models', 'app/services', 'tests']
            },
            'flask': {
                'files': ['app.py', 'requirements.txt', 'README.md', 'templates/index.html'],
                'structure': ['app', 'templates', 'static', 'tests']
            },
            'nodejs': {
                'files': ['index.js', 'package.json', 'README.md', '.env.example', 'Dockerfile'],
                'structure': ['src', 'tests', 'config', 'public']
            },
            'nextjs': {
                'files': ['package.json', 'pages/index.js', 'pages/_app.js', 'next.config.js'],
                'structure': ['pages', 'components', 'public', 'styles']
            }
        }
        
        self.tech_stack_features = {
            'react': {
                'hooks': True,
                'router': True,
                'state_management': 'context',
                'styling': 'css'
            },
            'fastapi': {
                'async': True,
                'orm': 'sqlalchemy',
                'validation': 'pydantic',
                'docs': 'swagger'
            },
            'nextjs': {
                'ssr': True,
                'api_routes': True,
                'image_optimization': True
            }
        }
    
    def generate_project(self, description: str, tech_stack: str = 'python', features: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Generate complete project from description
        
        Args:
            description: Natural language project description
            tech_stack: Technology stack to use
            features: Optional list of features to include
            
        Returns:
            Dict mapping file paths to content
        """
        files = {}
        features = features or []
        
        if tech_stack == 'python':
            files['main.py'] = self._generate_python_app(description)
            files['requirements.txt'] = self._generate_requirements(description, features)
            files['README.md'] = self._generate_readme(description, tech_stack)
            files['tests/test_main.py'] = self._generate_tests(description, tech_stack)
            files['.env.example'] = self._generate_env_file(description)
            files['.gitignore'] = self._generate_gitignore('python')
        
        elif tech_stack == 'fastapi':
            files['main.py'] = self._generate_fastapi_app(description)
            files['requirements.txt'] = self._generate_requirements(description, ['fastapi', 'uvicorn', 'pydantic'])
            files['README.md'] = self._generate_readme(description, tech_stack)
            files['Dockerfile'] = self._generate_dockerfile('python')
            files['app/__init__.py'] = ''
            files['app/models.py'] = self._generate_models(description)
            files['app/api/routes.py'] = self._generate_routes(description)
            files['tests/test_api.py'] = self._generate_api_tests(description)
            files['.env.example'] = self._generate_env_file(description)
        
        elif tech_stack == 'react':
            files['src/App.js'] = self._generate_react_app(description, features)
            files['src/index.js'] = self._generate_react_index()
            files['src/App.css'] = self._generate_css(description)
            files['package.json'] = self._generate_package_json(description, tech_stack)
            files['README.md'] = self._generate_readme(description, tech_stack)
            files['public/index.html'] = self._generate_html(description)
            files['.gitignore'] = self._generate_gitignore('node')
        
        elif tech_stack == 'nodejs':
            files['index.js'] = self._generate_nodejs_app(description)
            files['package.json'] = self._generate_package_json(description, tech_stack)
            files['README.md'] = self._generate_readme(description, tech_stack)
            files['Dockerfile'] = self._generate_dockerfile('node')
            files['.env.example'] = self._generate_env_file(description)
            files['.gitignore'] = self._generate_gitignore('node')
        
        elif tech_stack == 'flask':
            files['app.py'] = self._generate_flask_app(description)
            files['requirements.txt'] = self._generate_requirements(description, ['flask', 'flask-cors'])
            files['templates/index.html'] = self._generate_html(description)
            files['static/style.css'] = self._generate_css(description)
            files['README.md'] = self._generate_readme(description, tech_stack)
        
        return files
    
    def _generate_python_app(self, description: str) -> str:
        return f'''"""
{description}
Auto-generated by Aether AI
"""

def main():
    print("Application: {description}")
    # TODO: Implement core logic
    
if __name__ == "__main__":
    main()
'''
    
    def _generate_react_app(self, description: str) -> str:
        return f'''import React from 'react';

// {description}
// Auto-generated by Aether AI

function App() {{
  return (
    <div className="App">
      <h1>{description}</h1>
      <p>Your app is ready!</p>
    </div>
  );
}}

export default App;
'''
    
    def _generate_nodejs_app(self, description: str) -> str:
        return f'''// {description}
// Auto-generated by Aether AI

const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {{
  res.send('{description} - Server running!');
}});

app.listen(PORT, () => {{
  console.log(`Server running on port ${{PORT}}`);
}});
'''
    
    def _generate_requirements(self, description: str, extra_features: Optional[List[str]] = None) -> str:
        """Generate requirements.txt with intelligent dependencies"""
        base_deps = ['python-dotenv>=1.0.0', 'requests>=2.31.0']
        
        extra_features = extra_features or []
        
        deps = base_deps + extra_features
        
        if 'fastapi' in extra_features:
            deps.extend(['uvicorn[standard]>=0.24.0', 'pydantic>=2.0.0'])
        
        if 'database' in description.lower() or 'db' in description.lower():
            deps.append('sqlalchemy>=2.0.0')
        
        if 'api' in description.lower():
            deps.append('httpx>=0.25.0')
        
        return '\n'.join(sorted(set(deps))) + '\n'
    
    def _generate_package_json(self, description: str) -> str:
        return json.dumps({
            "name": description.lower().replace(' ', '-'),
            "version": "1.0.0",
            "description": description,
            "main": "index.js",
            "scripts": {
                "start": "node index.js",
                "test": "echo \"No tests yet\""
            },
            "dependencies": {}
        }, indent=2)
    
    def _generate_readme(self, description: str, tech: str) -> str:
        return f'''# {description}

Auto-generated by **Aether AI**

## Description
{description}

## Tech Stack
- **{tech.upper()}**

## Installation
```bash
# Install dependencies
{"pip install -r requirements.txt" if tech == "python" else "npm install"}
```

## Usage
```bash
# Run the application
{"python main.py" if tech == "python" else "npm start"}
```

## Generated by
Aether AI - JARVIS-Level Assistant
'''
    
    def _generate_tests(self, description: str, tech: str) -> str:
        if tech == 'python':
            return f'''import unittest
from main import main

class TestApp(unittest.TestCase):
    def test_main(self):
        # TODO: Add tests
        pass

if __name__ == '__main__':
    unittest.main()
'''
        return ''

    def _generate_fastapi_app(self, description: str) -> str:
        """Generate FastAPI application"""
        return f'''"""
{description}
FastAPI Application - Auto-generated by Aether AI
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import uvicorn

app = FastAPI(
    title="{description}",
    description="Auto-generated by Aether AI",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Item(BaseModel):
    id: Optional[int] = None
    name: str
    description: Optional[str] = None

@app.get("/")
async def root():
    return {{"message": "{description} API is running!"}}

@app.get("/items", response_model=List[Item])
async def list_items():
    return []

@app.post("/items", response_model=Item)
async def create_item(item: Item):
    return item

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
'''
    
    def _generate_flask_app(self, description: str) -> str:
        """Generate Flask application"""
        return f'''"""
{description}
Flask Application - Auto-generated by Aether AI
"""
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html', title="{description}")

@app.route('/api/health')
def health():
    return jsonify({{"status": "healthy", "app": "{description}"}})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
'''
    
    def _generate_react_index(self) -> str:
        """Generate React index.js"""
        return '''import React from 'react';
import ReactDOM from 'react-dom/client';
import './App.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
'''
    
    def _generate_html(self, description: str) -> str:
        """Generate index.html"""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{description}</title>
</head>
<body>
    <div id="root"></div>
    <h1>{description}</h1>
    <p>Auto-generated by Aether AI</p>
</body>
</html>
'''
    
    def _generate_css(self, description: str) -> str:
        """Generate CSS file"""
        return '''* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: #333;
    line-height: 1.6;
}

.App {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
    background: white;
    border-radius: 10px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.1);
}

h1 {
    color: #667eea;
    margin-bottom: 20px;
}
'''
    
    def _generate_dockerfile(self, runtime: str) -> str:
        """Generate Dockerfile"""
        if runtime == 'python':
            return '''FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]
'''
        elif runtime == 'node':
            return '''FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

CMD ["node", "index.js"]
'''
        return ''
    
    def _generate_env_file(self, description: str) -> str:
        """Generate .env.example file"""
        return '''# Environment Variables
# Copy this file to .env and fill in your values

# Application
APP_NAME="{}"
ENV=development
PORT=8000

# Database (if needed)
# DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# API Keys (if needed)
# API_KEY=your_api_key_here
'''.format(description)
    
    def _generate_gitignore(self, runtime: str) -> str:
        """Generate .gitignore"""
        if runtime == 'python':
            return '''# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
.venv/
*.egg-info/
dist/
build/

# Environment
.env
.env.local

# IDE
.vscode/
.idea/
*.swp
*.swo

# Testing
.coverage
htmlcov/
.pytest_cache/

# Logs
*.log
logs/
'''
        elif runtime == 'node':
            return '''# Node
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment
.env
.env.local
.env.*.local

# Production
dist/
build/

# IDE
.vscode/
.idea/

# Testing
coverage/

# Logs
*.log
logs/
'''
        return ''
    
    def _generate_models(self, description: str) -> str:
        """Generate database models"""
        return '''"""
Database Models
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class BaseDBModel(BaseModel):
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
'''
    
    def _generate_routes(self, description: str) -> str:
        """Generate API routes"""
        return '''"""
API Routes
"""
from fastapi import APIRouter, HTTPException
from typing import List

router = APIRouter()

@router.get("/health")
async def health_check():
    return {"status": "healthy"}
'''
    
    def _generate_api_tests(self, description: str) -> str:
        """Generate API tests"""
        return f'''"""
API Tests for {description}
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "message" in response.json()

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
'''


class CodeRefactorer:
    """Code analysis and refactoring tool"""
    
    def refactor(self, code: str, style: str = 'clean') -> str:
        """
        Refactor code according to style guide
        
        Args:
            code: Source code
            style: Style guide ('clean', 'pep8', 'google')
            
        Returns:
            Refactored code
        """
        lines = code.split('\n')
        refactored = []
        
        for line in lines:
            line = line.rstrip()
            
            if style == 'clean':
                if line and not line.strip().startswith('#'):
                    refactored.append(line)
            elif style == 'pep8':
                if len(line) > 79:
                    refactored.append(line[:79])
                else:
                    refactored.append(line)
            else:
                refactored.append(line)
        
        return '\n'.join(refactored)
    
    def find_bugs(self, code: str) -> List[Dict[str, Any]]:
        """
        Find potential bugs in code
        
        Returns:
            List of potential issues
        """
        issues = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if 'eval(' in line:
                issues.append({
                    'line': i,
                    'severity': 'high',
                    'message': 'Use of eval() is dangerous',
                    'code': line.strip()
                })
            
            if 'exec(' in line:
                issues.append({
                    'line': i,
                    'severity': 'high',
                    'message': 'Use of exec() is dangerous',
                    'code': line.strip()
                })
            
            if 'import *' in line:
                issues.append({
                    'line': i,
                    'severity': 'medium',
                    'message': 'Wildcard imports should be avoided',
                    'code': line.strip()
                })
            
            if re.search(r'password\s*=\s*["\']', line, re.IGNORECASE):
                issues.append({
                    'line': i,
                    'severity': 'critical',
                    'message': 'Hardcoded password detected',
                    'code': line.strip()
                })
        
        return issues


code_generator = AdvancedCodeGenerator()

def generate_app(description: str, tech_stack: str = 'python', features: Optional[List[str]] = None) -> Dict[str, str]:
    """
    Generate complete application from description
    
    Args:
        description: App description
        tech_stack: Technology to use
        features: Optional features list
        
    Returns:
        Dict of file paths to content
    """
    return code_generator.generate_project(description, tech_stack, features)

def create_project_files(description: str, tech_stack: str, output_dir: Path, features: Optional[List[str]] = None) -> int:
    """
    Create project files on disk
    
    Args:
        description: App description
        tech_stack: Technology to use
        output_dir: Output directory
        features: Optional features list
        
    Returns:
        Number of files created
    """
    files = generate_app(description, tech_stack, features)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for file_path, content in files.items():
        full_path = output_dir / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    print(f"✅ Created {len(files)} files in {output_dir}")
    return len(files)
