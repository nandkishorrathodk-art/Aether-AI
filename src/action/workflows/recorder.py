"""
Workflow Recorder - Record and replay user actions
This is a POWER FEATURE that Vy doesn't have!
"""

import time
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

try:
    from pynput import mouse, keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    print("Warning: pynput not available. Install with: pip install pynput")


class WorkflowRecorder:
    """Record user actions (mouse, keyboard) and replay them"""
    
    def __init__(self, workflow_dir: str = "workflows"):
        self.workflow_dir = Path(workflow_dir)
        self.workflow_dir.mkdir(exist_ok=True)
        
        self.recording = False
        self.actions: List[Dict[str, Any]] = []
        self.start_time = None
        self.mouse_listener = None
        self.keyboard_listener = None
    
    def start_recording(self, workflow_name: str = None):
        """Start recording user actions"""
        if not PYNPUT_AVAILABLE:
            raise RuntimeError("pynput not installed. Cannot record.")
        
        self.recording = True
        self.actions = []
        self.start_time = time.time()
        self.workflow_name = workflow_name or f"workflow_{int(time.time())}"
        
        print(f"📹 Recording workflow: {self.workflow_name}")
        print("Press ESC to stop recording")
        
        # Start listeners
        self.mouse_listener = mouse.Listener(
            on_move=self._on_mouse_move,
            on_click=self._on_mouse_click,
            on_scroll=self._on_mouse_scroll
        )
        self.keyboard_listener = keyboard.Listener(
            on_press=self._on_key_press,
            on_release=self._on_key_release
        )
        
        self.mouse_listener.start()
        self.keyboard_listener.start()
        
        return self.workflow_name
    
    def stop_recording(self):
        """Stop recording and save workflow"""
        if not self.recording:
            return None
        
        self.recording = False
        
        if self.mouse_listener:
            self.mouse_listener.stop()
        if self.keyboard_listener:
            self.keyboard_listener.stop()
        
        duration = time.time() - self.start_time
        
        workflow_data = {
            'name': self.workflow_name,
            'created': datetime.now().isoformat(),
            'duration': duration,
            'action_count': len(self.actions),
            'actions': self.actions
        }
        
        # Save workflow
        filepath = self.workflow_dir / f"{self.workflow_name}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(workflow_data, f, indent=2)
        
        print(f"✓ Workflow saved: {filepath}")
        print(f"  Actions recorded: {len(self.actions)}")
        print(f"  Duration: {duration:.2f}s")
        
        return filepath
    
    def replay_workflow(self, workflow_name: str, speed: float = 1.0):
        """Replay a saved workflow"""
        try:
            import pyautogui
        except ImportError:
            raise RuntimeError("pyautogui not installed. Cannot replay.")
        
        filepath = self.workflow_dir / f"{workflow_name}.json"
        
        if not filepath.exists():
            raise FileNotFoundError(f"Workflow not found: {workflow_name}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            workflow_data = json.load(f)
        
        print(f"▶️ Replaying workflow: {workflow_name}")
        print(f"  Actions: {workflow_data['action_count']}")
        print(f"  Speed: {speed}x")
        
        last_timestamp = 0
        
        for action in workflow_data['actions']:
            # Calculate delay
            delay = (action['timestamp'] - last_timestamp) / speed
            if delay > 0:
                time.sleep(delay)
            
            # Execute action
            try:
                if action['type'] == 'mouse_click':
                    pyautogui.click(action['x'], action['y'], button=action.get('button', 'left'))
                
                elif action['type'] == 'mouse_move':
                    pyautogui.moveTo(action['x'], action['y'])
                
                elif action['type'] == 'key_press':
                    key = action['key']
                    if key.startswith('Key.'):
                        key = key.replace('Key.', '')
                    pyautogui.press(key)
                
                elif action['type'] == 'type_text':
                    pyautogui.typewrite(action['text'], interval=0.05)
                
            except Exception as e:
                print(f"⚠️ Error executing action: {e}")
            
            last_timestamp = action['timestamp']
        
        print(f"✓ Workflow replay complete!")
    
    def list_workflows(self):
        """List all saved workflows"""
        workflows = []
        
        for filepath in self.workflow_dir.glob("*.json"):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                workflows.append({
                    'name': data['name'],
                    'created': data['created'],
                    'actions': data['action_count'],
                    'duration': data['duration']
                })
            except:
                pass
        
        return workflows
    
    def delete_workflow(self, workflow_name: str):
        """Delete a saved workflow"""
        filepath = self.workflow_dir / f"{workflow_name}.json"
        if filepath.exists():
            filepath.unlink()
            return True
        return False
    
    # Event handlers
    def _on_mouse_move(self, x, y):
        """Record mouse movement"""
        if not self.recording:
            return
        
        # Only record significant movements (reduce noise)
        if len(self.actions) > 0 and self.actions[-1]['type'] == 'mouse_move':
            last_x = self.actions[-1]['x']
            last_y = self.actions[-1]['y']
            
            # Skip if movement is small
            if abs(x - last_x) < 5 and abs(y - last_y) < 5:
                return
        
        self.actions.append({
            'type': 'mouse_move',
            'x': x,
            'y': y,
            'timestamp': time.time() - self.start_time
        })
    
    def _on_mouse_click(self, x, y, button, pressed):
        """Record mouse click"""
        if not self.recording or not pressed:
            return
        
        self.actions.append({
            'type': 'mouse_click',
            'x': x,
            'y': y,
            'button': str(button),
            'timestamp': time.time() - self.start_time
        })
    
    def _on_mouse_scroll(self, x, y, dx, dy):
        """Record mouse scroll"""
        if not self.recording:
            return
        
        self.actions.append({
            'type': 'mouse_scroll',
            'x': x,
            'y': y,
            'dx': dx,
            'dy': dy,
            'timestamp': time.time() - self.start_time
        })
    
    def _on_key_press(self, key):
        """Record key press"""
        if not self.recording:
            return
        
        # Stop recording on ESC
        try:
            if key == keyboard.Key.esc:
                self.stop_recording()
                return
        except:
            pass
        
        self.actions.append({
            'type': 'key_press',
            'key': str(key),
            'timestamp': time.time() - self.start_time
        })
    
    def _on_key_release(self, key):
        """Record key release"""
        pass  # We don't need to record releases for most cases


# CLI for testing
if __name__ == "__main__":
    import sys
    
    recorder = WorkflowRecorder()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "record":
            name = sys.argv[2] if len(sys.argv) > 2 else None
            recorder.start_recording(name)
            # Keep running until ESC is pressed
            recorder.keyboard_listener.join()
        
        elif command == "replay":
            if len(sys.argv) < 3:
                print("Usage: python recorder.py replay <workflow_name>")
                sys.exit(1)
            recorder.replay_workflow(sys.argv[2])
        
        elif command == "list":
            workflows = recorder.list_workflows()
            print(f"\n📁 Saved Workflows ({len(workflows)}):")
            for wf in workflows:
                print(f"  • {wf['name']}: {wf['actions']} actions, {wf['duration']:.1f}s")
        
        else:
            print("Unknown command. Use: record, replay, or list")
    else:
        print("Workflow Recorder")
        print("Usage:")
        print("  python recorder.py record [name]    - Start recording")
        print("  python recorder.py replay <name>    - Replay workflow")
        print("  python recorder.py list             - List saved workflows")
