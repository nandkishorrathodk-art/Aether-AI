
import asyncio
import sys
import os

# Add src to path
sys.path.append(os.getcwd())

from src.cognitive.llm.inference import conversation_engine, ConversationRequest

async def test_echo():
    print("Testing Conversation Engine...")
    request = ConversationRequest(
        user_input="How are you?",
        session_id="test_debug_echo"
    )
    
    try:
        response = await conversation_engine.process_conversation(request)
        print(f"User Input: {request.user_input}")
        print(f"AI Response: {response.content}")
        
        if "You said:" in response.content:
            print("FAILURE: Echo detected!")
        else:
            print("SUCCESS: No echo detected.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_echo())
