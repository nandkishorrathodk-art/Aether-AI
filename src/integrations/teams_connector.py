"""
Microsoft Teams integration for collaboration and communication.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import requests


@dataclass
class TeamsMessage:
    """Teams message representation."""
    id: str
    content: str
    sender: str
    timestamp: str
    channel_id: str


class TeamsConnector:
    """
    Microsoft Teams Graph API integration.
    
    Supports sending messages, managing channels, and team collaboration.
    """
    
    def __init__(self, access_token: str):
        """
        Initialize Teams connector.
        
        Args:
            access_token: Microsoft Graph API access token
        """
        self.token = access_token
        self.headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        self.base_url = 'https://graph.microsoft.com/v1.0'
    
    def send_message(self, team_id: str, channel_id: str, content: str) -> Dict[str, Any]:
        """
        Send a message to a Teams channel.
        
        Args:
            team_id: Team ID
            channel_id: Channel ID
            content: Message content (HTML supported)
            
        Returns:
            Message details
        """
        endpoint = f"{self.base_url}/teams/{team_id}/channels/{channel_id}/messages"
        
        payload = {
            'body': {
                'content': content,
                'contentType': 'html'
            }
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to send Teams message: {str(e)}")
    
    def send_adaptive_card(self, team_id: str, channel_id: str, card: Dict[str, Any]) -> Dict[str, Any]:
        """Send an Adaptive Card message."""
        endpoint = f"{self.base_url}/teams/{team_id}/channels/{channel_id}/messages"
        
        payload = {
            'body': {
                'contentType': 'html',
                'content': '<attachment id=\"74d20c7f34aa4a7fb74e2b30004247c5\"></attachment>'
            },
            'attachments': [
                {
                    'id': '74d20c7f34aa4a7fb74e2b30004247c5',
                    'contentType': 'application/vnd.microsoft.card.adaptive',
                    'content': card
                }
            ]
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to send adaptive card: {str(e)}")
    
    def get_messages(self, team_id: str, channel_id: str, limit: int = 50) -> List[TeamsMessage]:
        """Get channel messages."""
        endpoint = f"{self.base_url}/teams/{team_id}/channels/{channel_id}/messages"
        
        params = {'$top': limit}
        
        try:
            response = requests.get(endpoint, params=params, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            messages = []
            for msg in data.get('value', []):
                messages.append(TeamsMessage(
                    id=msg['id'],
                    content=msg['body']['content'],
                    sender=msg['from']['user']['displayName'] if msg.get('from') else 'Unknown',
                    timestamp=msg['createdDateTime'],
                    channel_id=channel_id
                ))
            
            return messages
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get messages: {str(e)}")
    
    def list_teams(self) -> List[Dict[str, str]]:
        """List all teams."""
        endpoint = f"{self.base_url}/me/joinedTeams"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return [
                {'id': team['id'], 'name': team['displayName']}
                for team in data.get('value', [])
            ]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to list teams: {str(e)}")
    
    def list_channels(self, team_id: str) -> List[Dict[str, str]]:
        """List channels in a team."""
        endpoint = f"{self.base_url}/teams/{team_id}/channels"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return [
                {'id': ch['id'], 'name': ch['displayName']}
                for ch in data.get('value', [])
            ]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to list channels: {str(e)}")
    
    def create_channel(self, team_id: str, name: str, description: str = "") -> Dict[str, Any]:
        """Create a new channel."""
        endpoint = f"{self.base_url}/teams/{team_id}/channels"
        
        payload = {
            'displayName': name,
            'description': description,
            'membershipType': 'standard'
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to create channel: {str(e)}")
    
    def send_notification(self, user_id: str, subject: str, message: str) -> Dict[str, Any]:
        """Send a notification/chat message to a user."""
        endpoint = f"{self.base_url}/users/{user_id}/sendMail"
        
        payload = {
            'message': {
                'subject': subject,
                'body': {
                    'contentType': 'Text',
                    'content': message
                },
                'toRecipients': [
                    {'emailAddress': {'address': user_id}}
                ]
            }
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            return {'status': 'sent'}
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to send notification: {str(e)}")
