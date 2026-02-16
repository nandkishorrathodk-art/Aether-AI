"""
Simple command-line chat interface for Aether AI
Run this while the server is running
"""

import requests
import json
import sys

API_URL = "http://127.0.0.1:8000"

def chat(message, session_id="user123"):
    """Send message to Aether AI"""
    try:
        response = requests.post(
            f"{API_URL}/api/v1/chat/conversation",
            json={
                "message": message,
                "session_id": session_id,
                "stream": False
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get("content", "No response")
        else:
            return f"Error: {response.status_code} - {response.text}"
    
    except Exception as e:
        return f"Error: {str(e)}"


def main():
    print("\n" + "="*60)
    print("         AETHER AI - COMMAND LINE CHAT")
    print("="*60)
    print("\nType 'quit' or 'exit' to stop")
    print("Type 'clear' to clear screen")
    print("="*60 + "\n")
    
    session_id = "cmd_chat_session"
    
    while True:
        try:
            # Get user input
            user_input = input("You: ").strip()
            
            if not user_input:
                continue
            
            # Check for commands
            if user_input.lower() in ['quit', 'exit', 'bye']:
                print("\nGoodbye! 👋\n")
                break
            
            if user_input.lower() == 'clear':
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                continue
            
            # Send to Aether AI
            print("\nAether AI: ", end="", flush=True)
            response = chat(user_input, session_id)
            print(response)
            print()
        
        except KeyboardInterrupt:
            print("\n\nGoodbye! 👋\n")
            break
        except Exception as e:
            print(f"\nError: {e}\n")


if __name__ == "__main__":
    # Check if server is running
    try:
        response = requests.get(f"{API_URL}/health", timeout=5)
        if response.status_code != 200:
            print("\n❌ Server is not running!")
            print("\nPlease start the server first:")
            print("  - Double-click: CLICK-ME.bat")
            print("  - Or run: RUN.bat")
            print("\nThen run this script again.\n")
            sys.exit(1)
    except Exception:
        print("\n❌ Cannot connect to Aether AI server!")
        print("\nPlease start the server first:")
        print("  - Double-click: CLICK-ME.bat")
        print("  - Or run: RUN.bat")
        print(f"\nMake sure server is running at: {API_URL}\n")
        sys.exit(1)
    
    # Start chat
    main()
