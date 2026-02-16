import webbrowser
from typing import Optional

class BrowserAutomation:
    """Handles web browser automation tasks"""
    
    @staticmethod
    def open_url(url: str):
        """Open a URL in the default browser"""
        if not url.startswith('http'):
            url = 'https://' + url
        webbrowser.open(url)
        return f"Opening {url}"

    @staticmethod
    def search(query: str):
        """Search Google for a query"""
        url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
        webbrowser.open(url)
        return f"Searching for '{query}'"

    @staticmethod
    def open_site_by_name(name: str):
        """Open a popular site by name"""
        sites = {
            "youtube": "https://youtube.com",
            "google": "https://google.com",
            "github": "https://github.com",
            "twitter": "https://twitter.com",
            "reddit": "https://reddit.com",
            "chatgpt": "https://chat.openai.com",
            "email": "https://gmail.com",
            "whatsapp": "https://web.whatsapp.com"
        }
        
        name = name.lower().strip()
        if name in sites:
            webbrowser.open(sites[name])
            return f"Opening {name}"
        else:
            # Fallback to search
            return BrowserAutomation.search(name)
