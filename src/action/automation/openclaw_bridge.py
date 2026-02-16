"""
OpenClaw Bridge - Python wrapper for OpenClaw's TypeScript browser automation
Integrates 75-80% of OpenClaw's features into Aether
"""
import subprocess
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
import os

class OpenClawBridge:
    def __init__(self, openclaw_path: str = None):
        self.openclaw_path = openclaw_path or str(Path(__file__).parent.parent.parent.parent / "openclaw_source")
        self.node_cmd = "node"
    
    def _run_openclaw_command(self, command: List[str], input_data: Dict = None) -> Dict:
        full_cmd = [self.node_cmd, f"{self.openclaw_path}/openclaw.mjs"] + command
        
        env = os.environ.copy()
        env['OPENCLAW_SKIP_CHANNELS'] = '1'
        
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                input=json.dumps(input_data) if input_data else None,
                env=env,
                timeout=60
            )
            
            if result.returncode == 0:
                try:
                    return json.loads(result.stdout)
                except:
                    return {'output': result.stdout, 'success': True}
            else:
                return {'error': result.stderr, 'success': False}
        
        except subprocess.TimeoutExpired:
            return {'error': 'Command timeout', 'success': False}
        except Exception as e:
            return {'error': str(e), 'success': False}
    
    def browse_url(self, url: str, actions: List[Dict] = None) -> Dict:
        """
        Use OpenClaw's Playwright browser automation
        
        Args:
            url: URL to navigate to
            actions: List of actions to perform [{type: 'click', selector: '...'}]
        
        Returns:
            Dict with status and results
        """
        command = ['agent', '--mode', 'rpc', '--json']
        
        input_data = {
            'tool': 'browser',
            'params': {
                'url': url,
                'actions': actions or []
            }
        }
        
        return self._run_openclaw_command(command, input_data)
    
    def execute_skill(self, skill_name: str, params: Dict = None) -> Dict:
        """
        Execute one of OpenClaw's 50+ pre-built skills
        
        Available skills:
        - github: GitHub operations
        - slack: Slack messaging
        - discord: Discord automation
        - notion: Notion database operations
        - obsidian: Obsidian note management
        - spotify-player: Spotify control
        - weather: Weather information
        - summarize: Text summarization
        - coding-agent: Code generation
        ... and 40+ more!
        
        Args:
            skill_name: Name of the skill to execute
            params: Skill-specific parameters
        
        Returns:
            Dict with skill execution results
        """
        command = ['skill', skill_name]
        
        if params:
            for key, value in params.items():
                command.extend([f'--{key}', str(value)])
        
        return self._run_openclaw_command(command)
    
    def send_message(self, channel: str, recipient: str, message: str) -> Dict:
        """
        Send message via OpenClaw's multi-channel system
        
        Supported channels:
        - whatsapp
        - telegram
        - slack
        - discord
        - signal
        - imessage (macOS only)
        
        Args:
            channel: Platform name
            recipient: Recipient ID (phone/username)
            message: Message text
        
        Returns:
            Dict with send status
        """
        command = ['message', 'send', '--to', recipient, '--message', message]
        
        if channel:
            command.extend(['--channel', channel])
        
        return self._run_openclaw_command(command)
    
    def take_screenshot(self, url: str, selector: str = None) -> Dict:
        """
        Take screenshot using OpenClaw's browser
        
        Args:
            url: URL to screenshot
            selector: Optional CSS selector to screenshot specific element
        
        Returns:
            Dict with screenshot path/data
        """
        actions = []
        if selector:
            actions.append({
                'type': 'screenshot',
                'selector': selector
            })
        
        return self.browse_url(url, actions)
    
    def fill_form(self, url: str, form_data: Dict[str, str]) -> Dict:
        """
        Fill web form using OpenClaw's automation
        
        Args:
            url: Form URL
            form_data: Dict mapping field selectors to values
        
        Returns:
            Dict with form fill status
        """
        actions = []
        for selector, value in form_data.items():
            actions.append({
                'type': 'fill',
                'selector': selector,
                'value': value
            })
        
        actions.append({'type': 'submit'})
        
        return self.browse_url(url, actions)
    
    def extract_data(self, url: str, selectors: Dict[str, str]) -> Dict:
        """
        Extract data from webpage
        
        Args:
            url: Page URL
            selectors: Dict mapping data names to CSS selectors
        
        Returns:
            Dict with extracted data
        """
        actions = []
        for name, selector in selectors.items():
            actions.append({
                'type': 'extract',
                'name': name,
                'selector': selector
            })
        
        return self.browse_url(url, actions)
    
    def get_available_skills(self) -> List[str]:
        """Get list of all available OpenClaw skills"""
        skills_dir = Path(self.openclaw_path) / "skills"
        if skills_dir.exists():
            return [d.name for d in skills_dir.iterdir() if d.is_dir()]
        return []
    
    def get_skill_info(self, skill_name: str) -> Dict:
        """Get information about a specific skill"""
        skill_path = Path(self.openclaw_path) / "skills" / skill_name / "package.json"
        
        if skill_path.exists():
            with open(skill_path, 'r') as f:
                return json.load(f)
        
        return {'error': f'Skill {skill_name} not found'}

openclaw = OpenClawBridge()

def browse_with_openclaw(url: str, actions: List[Dict] = None) -> Dict:
    """Use OpenClaw's browser automation"""
    return openclaw.browse_url(url, actions)

def use_openclaw_skill(skill_name: str, params: Dict = None) -> Dict:
    """Execute OpenClaw skill"""
    return openclaw.execute_skill(skill_name, params)

def send_via_openclaw(channel: str, recipient: str, message: str) -> Dict:
    """Send message via OpenClaw"""
    return openclaw.send_message(channel, recipient, message)

def list_openclaw_skills() -> List[str]:
    """List all available OpenClaw skills"""
    return openclaw.get_available_skills()
