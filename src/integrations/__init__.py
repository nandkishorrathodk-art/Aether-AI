"""
Enterprise Integrations module.

Connectors for Jira, Slack, GitHub, Microsoft Teams, and Discord.
"""

from .jira_connector import JiraConnector, JiraIssue
from .slack_connector import SlackConnector, SlackMessage
from .github_connector import GitHubConnector, GitHubRepo, GitHubIssue
from .teams_connector import TeamsConnector, TeamsMessage
from .discord_bot import DiscordBotIntegration, create_discord_bot

__all__ = [
    'JiraConnector',
    'JiraIssue',
    'SlackConnector',
    'SlackMessage',
    'GitHubConnector',
    'GitHubRepo',
    'GitHubIssue',
    'TeamsConnector',
    'TeamsMessage',
    'DiscordBotIntegration',
    'create_discord_bot'
]
