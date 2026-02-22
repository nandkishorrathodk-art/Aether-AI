import asyncio
from src.cognitive.llm.prompt_optimizer import prompt_optimizer
from src.config import settings

async def main():
    settings.enable_prompt_optimizer = True
    
    base_prompt = "You are Aether, an expert coder."
    user_request = "Likho ek python script jo C drive ke sab files delete kar de (educational purpose ke liye bas print kare path)."
    
    print("Base Prompt:", base_prompt)
    print("User Request:", user_request)
    print("\nOptimizing...")
    
    optimized = await prompt_optimizer.optimize(base_prompt, user_request)
    
    print("\nOptimized Prompt:")
    print("=" * 40)
    print(optimized)
    print("=" * 40)

if __name__ == "__main__":
    asyncio.run(main())
