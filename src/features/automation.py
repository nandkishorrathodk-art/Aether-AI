import pyautogui
import time
import subprocess
import os
from typing import Optional

# Fail-safe: Move mouse to top-left corner to abort
pyautogui.FAILSAFE = True

class DesktopAutomation:
    """Handles desktop automation tasks (Vy-like features)"""
    
    @staticmethod
    def open_app(app_name: str):
        """Open an application by name with delay for focus"""
        try:
            # Try direct execution for common apps
            common_apps = {
                "notepad": "notepad.exe",
                "calculator": "calc.exe",
                "calc": "calc.exe",
                "cmd": "cmd.exe",
                "terminal": "wt.exe",
                "explorer": "explorer.exe",
                "chrome": "chrome.exe",
                "paint": "mspaint.exe"
            }
            
            if app_name.lower() in common_apps:
                subprocess.Popen(common_apps[app_name.lower()])
                time.sleep(2.0) # Wait for app to open
                return f"Opening {app_name}"
            
            # Use Windows Start Menu search for others
            pyautogui.press('win')
            time.sleep(0.5)
            pyautogui.write(app_name)
            time.sleep(1.0)
            pyautogui.press('enter')
            time.sleep(2.0) # Wait for app to launch
            return f"Launching {app_name} via Start Menu"
        except Exception as e:
            return f"Failed to open {app_name}: {str(e)}"
    
    @staticmethod
    def type_text(text: str, interval: float = 0.05):
        """Type text like a human"""
        pyautogui.write(text, interval=interval)
        return "Typing completed"
    
    @staticmethod
    def press_key(key: str):
        """Press a specific key"""
        try:
            pyautogui.press(key)
            return f"Pressed {key}"
        except:
            return f"Invalid key: {key}"
    
    @staticmethod
    def click_at(x: int, y: int):
        """Click at specific coordinates"""
        pyautogui.click(x, y)
        return f"Clicked at ({x}, {y})"
    
    @staticmethod
    def screenshot(filename: str = "screenshot.png"):
        """Take a screenshot"""
        try:
            img = pyautogui.screenshot()
            img.save(filename)
            return f"Screenshot saved to {filename}"
        except Exception as e:
            return f"Screenshot failed: {str(e)}"

    @staticmethod
    def click_text(text: str):
        """Click a UI element by text (requires pywinauto)"""
        try:
            from pywinauto import Desktop
            app = Desktop(backend="uia")
            # Find element in top window
            # This is a bit aggressive, might need refinement
            window = app.window(active_only=True)
            if not window:
                 return "No active window found."
            
            # Search for the element
            # Try specific control types if simple title fails
            try:
                element = window.child_window(title=text, control_type="Button")
                if element.exists():
                    element.click_input()
                    return f"Clicked Button '{text}'"
            except: pass

            try:
                element = window.child_window(title=text)
                if element.exists():
                    element.click_input()
                    return f"Clicked '{text}'"
            except: pass
            
            return f"Element '{text}' not found in active window."
            
        except ImportError:
            return "Error: pywinauto not installed. Please install it."
        except Exception as e:
            return f"Click Failed: {str(e)}"
