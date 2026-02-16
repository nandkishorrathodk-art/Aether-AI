"""
GitHub integration for repository management and automation.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import requests


@dataclass
class GitHubRepo:
    """GitHub repository representation."""
    name: str
    full_name: str
    description: str
    url: str
    stars: int
    forks: int
    language: str


@dataclass
class GitHubIssue:
    """GitHub issue representation."""
    number: int
    title: str
    body: str
    state: str
    labels: List[str]
    assignee: Optional[str]
    created_at: str
    updated_at: str


class GitHubConnector:
    """
    GitHub API integration for repositories, issues, PRs, and actions.
    """
    
    def __init__(self, token: str):
        """
        Initialize GitHub connector.
        
        Args:
            token: GitHub Personal Access Token
        """
        self.token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.base_url = 'https://api.github.com'
    
    def get_repo(self, owner: str, repo: str) -> GitHubRepo:
        """Get repository details."""
        endpoint = f"{self.base_url}/repos/{owner}/{repo}"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return GitHubRepo(
                name=data['name'],
                full_name=data['full_name'],
                description=data.get('description', ''),
                url=data['html_url'],
                stars=data['stargazers_count'],
                forks=data['forks_count'],
                language=data.get('language', 'Unknown')
            )
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get repo: {str(e)}")
    
    def create_issue(self, owner: str, repo: str, title: str, body: str,
                    labels: Optional[List[str]] = None) -> GitHubIssue:
        """Create a new issue."""
        endpoint = f"{self.base_url}/repos/{owner}/{repo}/issues"
        
        payload = {
            'title': title,
            'body': body
        }
        
        if labels:
            payload['labels'] = labels
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return self._parse_issue(data)
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to create issue: {str(e)}")
    
    def get_issue(self, owner: str, repo: str, issue_number: int) -> GitHubIssue:
        """Get issue details."""
        endpoint = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            return self._parse_issue(response.json())
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get issue: {str(e)}")
    
    def list_issues(self, owner: str, repo: str, state: str = "open") -> List[GitHubIssue]:
        """List repository issues."""
        endpoint = f"{self.base_url}/repos/{owner}/{repo}/issues"
        
        params = {'state': state}
        
        try:
            response = requests.get(endpoint, params=params, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return [self._parse_issue(issue) for issue in data]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to list issues: {str(e)}")
    
    def create_pr(self, owner: str, repo: str, title: str, head: str,
                 base: str, body: str = "") -> Dict[str, Any]:
        """Create a pull request."""
        endpoint = f"{self.base_url}/repos/{owner}/{repo}/pulls"
        
        payload = {
            'title': title,
            'head': head,
            'base': base,
            'body': body
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to create PR: {str(e)}")
    
    def list_repos(self, user: Optional[str] = None) -> List[GitHubRepo]:
        """List repositories."""
        if user:
            endpoint = f"{self.base_url}/users/{user}/repos"
        else:
            endpoint = f"{self.base_url}/user/repos"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return [
                GitHubRepo(
                    name=repo['name'],
                    full_name=repo['full_name'],
                    description=repo.get('description', ''),
                    url=repo['html_url'],
                    stars=repo['stargazers_count'],
                    forks=repo['forks_count'],
                    language=repo.get('language', 'Unknown')
                )
                for repo in data
            ]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to list repos: {str(e)}")
    
    def create_repo(self, name: str, description: str = "",
                   private: bool = False) -> GitHubRepo:
        """Create a new repository."""
        endpoint = f"{self.base_url}/user/repos"
        
        payload = {
            'name': name,
            'description': description,
            'private': private
        }
        
        try:
            response = requests.post(endpoint, json=payload, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return GitHubRepo(
                name=data['name'],
                full_name=data['full_name'],
                description=data.get('description', ''),
                url=data['html_url'],
                stars=0,
                forks=0,
                language='Unknown'
            )
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to create repo: {str(e)}")
    
    def get_commits(self, owner: str, repo: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent commits."""
        endpoint = f"{self.base_url}/repos/{owner}/{repo}/commits"
        
        params = {'per_page': limit}
        
        try:
            response = requests.get(endpoint, params=params, headers=self.headers)
            response.raise_for_status()
            
            data = response.json()
            
            return [
                {
                    'sha': commit['sha'][:7],
                    'message': commit['commit']['message'],
                    'author': commit['commit']['author']['name'],
                    'date': commit['commit']['author']['date']
                }
                for commit in data
            ]
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get commits: {str(e)}")
    
    def _parse_issue(self, data: Dict[str, Any]) -> GitHubIssue:
        """Parse GitHub API issue response."""
        return GitHubIssue(
            number=data['number'],
            title=data['title'],
            body=data.get('body', ''),
            state=data['state'],
            labels=[label['name'] for label in data.get('labels', [])],
            assignee=data['assignee']['login'] if data.get('assignee') else None,
            created_at=data['created_at'],
            updated_at=data['updated_at']
        )
