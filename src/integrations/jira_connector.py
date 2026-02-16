"""
Jira integration for task management and issue tracking.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import requests
from datetime import datetime


@dataclass
class JiraIssue:
    """Jira issue representation."""
    key: str
    summary: str
    description: str
    status: str
    priority: str
    assignee: Optional[str]
    reporter: str
    created: str
    updated: str
    issue_type: str


class JiraConnector:
    """
    Jira API integration for issue tracking and project management.
    
    Supports creating, updating, querying, and analyzing Jira issues.
    """
    
    def __init__(self, url: str, email: str, api_token: str):
        """
        Initialize Jira connector.
        
        Args:
            url: Jira instance URL (e.g., https://company.atlassian.net)
            email: User email
            api_token: API token from Jira
        """
        self.url = url.rstrip('/')
        self.auth = (email, api_token)
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    
    def create_issue(self, project_key: str, summary: str, description: str,
                    issue_type: str = "Task", priority: str = "Medium") -> JiraIssue:
        """
        Create a new Jira issue.
        
        Args:
            project_key: Project key (e.g., "PROJ")
            summary: Issue summary/title
            description: Detailed description
            issue_type: Type (Task, Bug, Story, etc.)
            priority: Priority level
            
        Returns:
            Created JiraIssue
        """
        endpoint = f"{self.url}/rest/api/3/issue"
        
        payload = {
            'fields': {
                'project': {'key': project_key},
                'summary': summary,
                'description': {
                    'type': 'doc',
                    'version': 1,
                    'content': [
                        {
                            'type': 'paragraph',
                            'content': [
                                {'type': 'text', 'text': description}
                            ]
                        }
                    ]
                },
                'issuetype': {'name': issue_type},
                'priority': {'name': priority}
            }
        }
        
        try:
            response = requests.post(
                endpoint,
                json=payload,
                auth=self.auth,
                headers=self.headers
            )
            
            response.raise_for_status()
            
            data = response.json()
            issue_key = data['key']
            
            return self.get_issue(issue_key)
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to create Jira issue: {str(e)}")
    
    def get_issue(self, issue_key: str) -> JiraIssue:
        """
        Get issue details.
        
        Args:
            issue_key: Issue key (e.g., "PROJ-123")
            
        Returns:
            JiraIssue object
        """
        endpoint = f"{self.url}/rest/api/3/issue/{issue_key}"
        
        try:
            response = requests.get(
                endpoint,
                auth=self.auth,
                headers=self.headers
            )
            
            response.raise_for_status()
            
            data = response.json()
            
            return self._parse_issue(data)
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get Jira issue: {str(e)}")
    
    def update_issue(self, issue_key: str, fields: Dict[str, Any]) -> JiraIssue:
        """
        Update an existing issue.
        
        Args:
            issue_key: Issue key
            fields: Fields to update (e.g., {'summary': 'New title', 'status': 'In Progress'})
            
        Returns:
            Updated JiraIssue
        """
        endpoint = f"{self.url}/rest/api/3/issue/{issue_key}"
        
        payload = {'fields': fields}
        
        try:
            response = requests.put(
                endpoint,
                json=payload,
                auth=self.auth,
                headers=self.headers
            )
            
            response.raise_for_status()
            
            return self.get_issue(issue_key)
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to update Jira issue: {str(e)}")
    
    def transition_issue(self, issue_key: str, transition_name: str) -> JiraIssue:
        """
        Transition issue to different status.
        
        Args:
            issue_key: Issue key
            transition_name: Transition name (e.g., "To Do", "In Progress", "Done")
            
        Returns:
            Updated JiraIssue
        """
        transitions = self.get_transitions(issue_key)
        
        transition_id = None
        for transition in transitions:
            if transition['name'].lower() == transition_name.lower():
                transition_id = transition['id']
                break
        
        if not transition_id:
            raise ValueError(f"Transition '{transition_name}' not found for issue {issue_key}")
        
        endpoint = f"{self.url}/rest/api/3/issue/{issue_key}/transitions"
        
        payload = {'transition': {'id': transition_id}}
        
        try:
            response = requests.post(
                endpoint,
                json=payload,
                auth=self.auth,
                headers=self.headers
            )
            
            response.raise_for_status()
            
            return self.get_issue(issue_key)
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to transition issue: {str(e)}")
    
    def get_transitions(self, issue_key: str) -> List[Dict[str, str]]:
        """Get available transitions for an issue."""
        endpoint = f"{self.url}/rest/api/3/issue/{issue_key}/transitions"
        
        try:
            response = requests.get(
                endpoint,
                auth=self.auth,
                headers=self.headers
            )
            
            response.raise_for_status()
            
            data = response.json()
            
            return [{'id': t['id'], 'name': t['name']} for t in data['transitions']]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get transitions: {str(e)}")
    
    def search_issues(self, jql: str, max_results: int = 50) -> List[JiraIssue]:
        """
        Search issues using JQL.
        
        Args:
            jql: JQL query (e.g., "project = PROJ AND status = Open")
            max_results: Maximum number of results
            
        Returns:
            List of JiraIssue objects
        """
        endpoint = f"{self.url}/rest/api/3/search"
        
        params = {
            'jql': jql,
            'maxResults': max_results
        }
        
        try:
            response = requests.get(
                endpoint,
                params=params,
                auth=self.auth,
                headers=self.headers
            )
            
            response.raise_for_status()
            
            data = response.json()
            
            return [self._parse_issue(issue) for issue in data['issues']]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to search issues: {str(e)}")
    
    def add_comment(self, issue_key: str, comment: str) -> Dict[str, Any]:
        """Add comment to an issue."""
        endpoint = f"{self.url}/rest/api/3/issue/{issue_key}/comment"
        
        payload = {
            'body': {
                'type': 'doc',
                'version': 1,
                'content': [
                    {
                        'type': 'paragraph',
                        'content': [
                            {'type': 'text', 'text': comment}
                        ]
                    }
                ]
            }
        }
        
        try:
            response = requests.post(
                endpoint,
                json=payload,
                auth=self.auth,
                headers=self.headers
            )
            
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to add comment: {str(e)}")
    
    def get_project_issues(self, project_key: str, status: Optional[str] = None) -> List[JiraIssue]:
        """Get all issues for a project."""
        jql = f"project = {project_key}"
        
        if status:
            jql += f" AND status = '{status}'"
        
        jql += " ORDER BY created DESC"
        
        return self.search_issues(jql)
    
    def get_user_issues(self, email: str, status: Optional[str] = None) -> List[JiraIssue]:
        """Get issues assigned to a user."""
        jql = f"assignee = '{email}'"
        
        if status:
            jql += f" AND status = '{status}'"
        
        jql += " ORDER BY created DESC"
        
        return self.search_issues(jql)
    
    def _parse_issue(self, data: Dict[str, Any]) -> JiraIssue:
        """Parse Jira API response to JiraIssue object."""
        fields = data['fields']
        
        description = ""
        if fields.get('description'):
            desc_content = fields['description'].get('content', [])
            for item in desc_content:
                if item.get('type') == 'paragraph':
                    for content in item.get('content', []):
                        if content.get('type') == 'text':
                            description += content.get('text', '')
        
        assignee = None
        if fields.get('assignee'):
            assignee = fields['assignee'].get('displayName')
        
        return JiraIssue(
            key=data['key'],
            summary=fields.get('summary', ''),
            description=description,
            status=fields['status']['name'],
            priority=fields['priority']['name'],
            assignee=assignee,
            reporter=fields['reporter']['displayName'],
            created=fields['created'],
            updated=fields['updated'],
            issue_type=fields['issuetype']['name']
        )
    
    def get_project_stats(self, project_key: str) -> Dict[str, Any]:
        """Get statistics for a project."""
        issues = self.get_project_issues(project_key)
        
        status_counts = {}
        priority_counts = {}
        type_counts = {}
        
        for issue in issues:
            status_counts[issue.status] = status_counts.get(issue.status, 0) + 1
            priority_counts[issue.priority] = priority_counts.get(issue.priority, 0) + 1
            type_counts[issue.issue_type] = type_counts.get(issue.issue_type, 0) + 1
        
        return {
            'total_issues': len(issues),
            'status_breakdown': status_counts,
            'priority_breakdown': priority_counts,
            'type_breakdown': type_counts
        }
