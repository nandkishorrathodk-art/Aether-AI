"""
BurpSuite UI Element Definitions
Element identifiers for intelligent detection
"""
from typing import Dict, Any, List
from src.automation.element_detector import DetectionStrategy


class BurpSuiteElements:
    """BurpSuite UI element identifiers and detection strategies"""
    
    # Main window elements
    BURPSUITE_TITLE = "Burp Suite Professional"
    
    # Startup elements
    TEMPORARY_PROJECT = "temporary project"
    DISK_PROJECT = "project on disk"
    NEXT_BUTTON = "Next"
    START_BURP = "Start Burp"
    
    # Main tabs
    PROXY_TAB = "Proxy"
    TARGET_TAB = "Target"
    INTRUDER_TAB = "Intruder"
    REPEATER_TAB = "Repeater"
    SCANNER_TAB = "Scanner"
    EXTENDER_TAB = "Extender"
    
    # Proxy sub-tabs
    INTERCEPT_TAB = "Intercept"
    HTTP_HISTORY_TAB = "HTTP history"
    WEBSOCKETS_HISTORY_TAB = "WebSockets history"
    OPTIONS_TAB = "Options"
    
    # Intercept controls
    INTERCEPT_ON_BUTTON = "Intercept is on"
    INTERCEPT_OFF_BUTTON = "Intercept is off"
    FORWARD_BUTTON = "Forward"
    DROP_BUTTON = "Drop"
    
    # Target controls
    SITE_MAP = "Site map"
    SCOPE = "Scope"
    ADD_TO_SCOPE = "Add to scope"
    
    # Scanner controls
    NEW_SCAN = "New scan"
    SCAN_STATUS = "Scan status"
    ISSUE_ACTIVITY = "Issue activity"
    
    @classmethod
    def get_detection_config(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get detection configuration for each element
        Returns dict mapping element name to detection strategies
        """
        return {
            # Startup flow
            "temporary_project": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT,
                    DetectionStrategy.IMAGE_MATCH
                ],
                "identifiers": [
                    cls.TEMPORARY_PROJECT,
                    "temporary_project_button.png"
                ]
            },
            "next_button": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT
                ],
                "identifiers": [cls.NEXT_BUTTON]
            },
            "start_burp": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT
                ],
                "identifiers": [cls.START_BURP]
            },
            
            # Main tabs
            "proxy_tab": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT,
                    DetectionStrategy.IMAGE_MATCH
                ],
                "identifiers": [
                    cls.PROXY_TAB,
                    "proxy_tab.png"
                ]
            },
            "target_tab": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT
                ],
                "identifiers": [cls.TARGET_TAB]
            },
            "scanner_tab": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT
                ],
                "identifiers": [cls.SCANNER_TAB]
            },
            
            # Intercept controls
            "intercept_tab": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT
                ],
                "identifiers": [cls.INTERCEPT_TAB]
            },
            "intercept_toggle": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT,
                    DetectionStrategy.IMAGE_MATCH
                ],
                "identifiers": [
                    cls.INTERCEPT_ON_BUTTON,
                    cls.INTERCEPT_OFF_BUTTON,
                    "intercept_button.png"
                ]
            },
            "forward_button": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT
                ],
                "identifiers": [cls.FORWARD_BUTTON]
            },
            
            # Scanner controls
            "new_scan": {
                "strategies": [
                    DetectionStrategy.ACCESSIBILITY,
                    DetectionStrategy.OCR_TEXT,
                    DetectionStrategy.IMAGE_MATCH
                ],
                "identifiers": [
                    cls.NEW_SCAN,
                    "new_scan_button.png"
                ]
            }
        }
    
    @classmethod
    def get_element_identifier(cls, element_name: str) -> str:
        """Get primary identifier for an element"""
        config = cls.get_detection_config()
        if element_name in config:
            return config[element_name]["identifiers"][0]
        return element_name
    
    @classmethod
    def get_element_strategies(cls, element_name: str) -> List[DetectionStrategy]:
        """Get detection strategies for an element"""
        config = cls.get_detection_config()
        if element_name in config:
            return config[element_name]["strategies"]
        return [DetectionStrategy.ACCESSIBILITY, DetectionStrategy.OCR_TEXT]


# Keyboard shortcuts (fallback when UI detection fails)
class BurpSuiteShortcuts:
    """BurpSuite keyboard shortcuts"""
    
    # Intercept
    TOGGLE_INTERCEPT = "ctrl+shift+i"
    FORWARD = "ctrl+f"
    DROP = "ctrl+d"
    
    # Navigation
    NEXT_TAB = "ctrl+tab"
    PREV_TAB = "ctrl+shift+tab"
    
    # Scanner
    PASSIVE_SCAN = "ctrl+shift+p"
    ACTIVE_SCAN = "ctrl+shift+a"
    
    # General
    SEARCH = "ctrl+f"
    SETTINGS = "ctrl+,"
