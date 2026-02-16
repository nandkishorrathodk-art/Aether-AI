"""
Slack integration for team communication and notifications.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import requests


@dataclass
class SlackMessage:
    """Slack message representation."""
    ts: str
    text: str
    user: str
    channel: str
    timestamp: str


class SlackConnector:
    """
    Slack API integration for messaging, channels, and user management.
    """
    
    def __init__(self, bot_token: str):
        """
        Initialize Slack connector.
        
        Args:
            bot_token: Slack Bot User OAuth Token (starts with xoxb-)
        """
        self.token = bot_token
        self.headers = {
            'Authorization': f'Bearer {bot_token}',
            'Content-Type': 'application/json'
        }
        self.base_url = 'https://slack.com/api'
    
    def send_message(self, channel: str, text: str, thread_ts: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a message to a channel.
        
        Args:
            channel: Channel ID or name
            text: Message text
            thread_ts: Thread timestamp for replies
            
        Returns:
            API response with message details
        """
        endpoint = f"{self.base_url}/chat.postMessage"
        
        payload = {
            'channel': channel,
            'text': text
        }
        
        if thread_ts:
            payload['thread_ts'] = thread_ts
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get('ok'):
                raise Exception(f"Slack API error: {data.get('error', 'Unknown error')}")
            
            return data
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to send Slack message: {str(e)}")
    
    def send_rich_message(self, channel: str, blocks: List[Dict[str, Any]],
                         text: str = "Message") -> Dict[str, Any]:
        """Send a rich message with Block Kit."""
        endpoint = f"{self.base_url}/chat.postMessage"
        
        payload = {
            'channel': channel,
            'blocks': blocks,
            'text': text
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get('ok'):
                raise Exception(f"Slack API error: {data.get('error')}")
            
            return data
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to send rich message: {str(e)}")
    
    def get_channel_history(self, channel: str, limit: int = 100) -> List[SlackMessage]:
        """Get message history from a channel."""
        endpoint = f"{self.base_url}/conversations.history"
        
        params = {
            'channel': channel,
            'limit': limit
        }
        
        try:
            response = requests.get(endpoint, params=params, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get('ok'):
                raise Exception(f"Slack API error: {data.get('error')}")
            
            messages = []
            for msg in data.get('messages', []):
                messages.append(SlackMessage(
                    ts=msg['ts'],
                    text=msg.get('text', ''),
                    user=msg.get('user', 'unknown'),
                    channel=channel,
                    timestamp=msg['ts']
                ))
            
            return messages
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get channel history: {str(e)}")
    
    def list_channels(self) -> List[Dict[str, str]]:
        """List all channels."""
        endpoint = f"{self.base_url}/conversations.list"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get('ok'):
                raise Exception(f"Slack API error: {data.get('error')}")
            
            return [
                {'id': ch['id'], 'name': ch['name']}
                for ch in data.get('channels', [])
            ]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to list channels: {str(e)}")
    
    def create_channel(self, name: str, is_private: bool = False) -> Dict[str, Any]:
        """Create a new channel."""
        endpoint = f"{self.base_url}/conversations.create"
        
        payload = {
            'name': name,
            'is_private': is_private
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get('ok'):
                raise Exception(f"Slack API error: {data.get('error')}")
            
            return data['channel']
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to create channel: {str(e)}")
    
    def add_reaction(self, channel: str, timestamp: str, emoji: str) -> Dict[str, Any]:
        """Add emoji reaction to a message."""
        endpoint = f"{self.base_url}/reactions.add"
        
        payload = {
            'channel': channel,
            'timestamp': timestamp,
            'name': emoji.replace(':', '')
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to add reaction: {str(e)}")
    
    def send_file(self, channels: str, file_path: str, title: Optional[str] = None) -> Dict[str, Any]:
        """Upload a file to Slack."""
        endpoint = f"{self.base_url}/files.upload"
        
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {'channels': channels}
            
            if title:
                data['title'] = title
            
            try:
                response = requests.post(
                    endpoint,
                    data=data,
                    files=files,
                    headers={'Authorization': f'Bearer {self.token}'}
                )
                
                response.raise_for_status()
                
                return response.json()
                
            except requests.exceptions.RequestException as e:
                raise Exception(f"Failed to upload file: {str(e)}")
