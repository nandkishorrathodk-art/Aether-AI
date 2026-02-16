"""
Discord Bot Integration for Aether AI (Mekio-style)

Allows Aether to connect to Discord as a bot and interact in servers.
"""

import discord
from discord.ext import commands
from typing import Optional, Dict, Any, List
import asyncio
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class DiscordBotIntegration:
    """
    Discord bot integration for Aether AI.
    
    Features:
    - Connect to Discord with bot token
    - Respond to messages and commands
    - AI-powered responses using Aether's LLM
    - Personality-based interactions
    - Voice channel support
    """
    
    def __init__(self, token: str, llm_provider=None, personality: str = 'friendly'):
        """
        Initialize Discord bot.
        
        Args:
            token: Discord bot token
            llm_provider: LLM provider for AI responses
            personality: Bot personality (friendly, playful, professional, kawaii, tsundere)
        """
        self.token = token
        self.llm_provider = llm_provider
        self.personality = personality
        
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True
        intents.voice_states = True
        
        self.bot = commands.Bot(command_prefix='!aether ', intents=intents)
        self.conversation_history: Dict[int, List[Dict]] = {}
        
        self._setup_commands()
        self._setup_events()
    
    def _setup_events(self):
        """Setup Discord event handlers."""
        
        @self.bot.event
        async def on_ready():
            logger.info(f'Discord bot logged in as {self.bot.user}')
            await self.bot.change_presence(
                activity=discord.Game(name="with Aether AI | !aether help")
            )
        
        @self.bot.event
        async def on_message(message):
            if message.author == self.bot.user:
                return
            
            if self.bot.user.mentioned_in(message) and not message.mention_everyone:
                await self._handle_mention(message)
            
            await self.bot.process_commands(message)
        
        @self.bot.event
        async def on_message_edit(before, after):
            if after.author == self.bot.user:
                return
            
            if self.bot.user.mentioned_in(after):
                await self._handle_mention(after, is_edit=True)
        
        @self.bot.event
        async def on_reaction_add(reaction, user):
            if user == self.bot.user:
                return
            
            if reaction.emoji == '❤️' and reaction.message.author == self.bot.user:
                await reaction.message.add_reaction('💕')
    
    def _setup_commands(self):
        """Setup Discord bot commands."""
        
        @self.bot.command(name='chat', help='Chat with Aether AI')
        async def chat(ctx, *, message: str):
            """Chat with Aether AI."""
            async with ctx.typing():
                response = await self._generate_response(
                    message,
                    user_id=ctx.author.id,
                    username=ctx.author.display_name
                )
            
            await ctx.reply(response)
        
        @self.bot.command(name='personality', help='Change bot personality')
        async def personality(ctx, new_personality: str):
            """Change bot personality."""
            valid_personalities = ['friendly', 'playful', 'professional', 'kawaii', 'tsundere']
            
            if new_personality.lower() not in valid_personalities:
                await ctx.reply(
                    f"Invalid personality! Choose from: {', '.join(valid_personalities)}"
                )
                return
            
            self.personality = new_personality.lower()
            
            responses = {
                'friendly': "Sure! I'm now in friendly mode. How can I help you? 😊",
                'playful': "Ooh, playful mode activated! Let's have some fun! 😜",
                'professional': "Personality updated to professional mode. Ready to assist. 💼",
                'kawaii': "Kyaa~! Kawaii mode activated! (◕‿◕)✿ Let's be friends! 🎀",
                'tsundere': "I-It's not like I wanted to change for you or anything! B-Baka! 😤"
            }
            
            await ctx.reply(responses[self.personality])
        
        @self.bot.command(name='clear', help='Clear conversation history')
        async def clear(ctx):
            """Clear conversation history for the user."""
            user_id = ctx.author.id
            
            if user_id in self.conversation_history:
                del self.conversation_history[user_id]
                await ctx.reply("Conversation history cleared! ✨")
            else:
                await ctx.reply("No conversation history to clear!")
        
        @self.bot.command(name='status', help='Check bot status')
        async def status(ctx):
            """Check bot status."""
            embed = discord.Embed(
                title="Aether AI Status",
                description="Bot is operational!",
                color=discord.Color.from_rgb(0, 255, 255)
            )
            
            embed.add_field(name="Personality", value=self.personality.capitalize(), inline=True)
            embed.add_field(name="Servers", value=str(len(self.bot.guilds)), inline=True)
            embed.add_field(name="Latency", value=f"{round(self.bot.latency * 1000)}ms", inline=True)
            
            llm_status = "Connected" if self.llm_provider else "Not configured"
            embed.add_field(name="AI Status", value=llm_status, inline=True)
            
            embed.set_footer(text=f"Requested by {ctx.author.display_name}")
            embed.timestamp = datetime.utcnow()
            
            await ctx.reply(embed=embed)
        
        @self.bot.command(name='analyze', help='Analyze text with AI')
        async def analyze(ctx, *, text: str):
            """Analyze text using AI."""
            async with ctx.typing():
                analysis = await self._analyze_text(text)
            
            embed = discord.Embed(
                title="AI Analysis",
                description=analysis,
                color=discord.Color.from_rgb(0, 255, 255)
            )
            
            await ctx.reply(embed=embed)
        
        @self.bot.command(name='translate', help='Translate text')
        async def translate(ctx, target_lang: str, *, text: str):
            """Translate text to another language."""
            async with ctx.typing():
                translation = await self._translate_text(text, target_lang)
            
            await ctx.reply(f"**Translation ({target_lang}):**\n{translation}")
        
        @self.bot.command(name='joke', help='Tell a joke')
        async def joke(ctx):
            """Tell a random joke."""
            async with ctx.typing():
                joke_text = await self._generate_joke()
            
            await ctx.reply(joke_text)
    
    async def _handle_mention(self, message, is_edit: bool = False):
        """Handle bot mentions."""
        content = message.content.replace(f'<@{self.bot.user.id}>', '').strip()
        
        if not content:
            await message.reply("Hi! How can I help you? Use `!aether help` for commands!")
            return
        
        async with message.channel.typing():
            response = await self._generate_response(
                content,
                user_id=message.author.id,
                username=message.author.display_name
            )
        
        if is_edit:
            await message.reply(f"*(Updated response)* {response}")
        else:
            await message.reply(response)
    
    async def _generate_response(self, message: str, user_id: int, username: str) -> str:
        """Generate AI response to user message."""
        if not self.llm_provider:
            return "AI provider not configured. Please set up an LLM provider!"
        
        if user_id not in self.conversation_history:
            self.conversation_history[user_id] = []
        
        personality_prompts = {
            'friendly': "You are a friendly and helpful AI assistant. Be warm and supportive.",
            'playful': "You are a playful and energetic AI assistant. Use emojis and be fun!",
            'professional': "You are a professional AI assistant. Be formal and efficient.",
            'kawaii': "You are a cute anime-style AI assistant. Use kawaii expressions and be adorable! (◕‿◕)✿",
            'tsundere': "You are a tsundere AI assistant. Be initially cold but caring underneath. Use phrases like 'B-Baka!' and 'It's not like I...'"
        }
        
        system_prompt = personality_prompts.get(self.personality, personality_prompts['friendly'])
        
        self.conversation_history[user_id].append({
            'role': 'user',
            'content': message
        })
        
        if len(self.conversation_history[user_id]) > 10:
            self.conversation_history[user_id] = self.conversation_history[user_id][-10:]
        
        try:
            response = self.llm_provider.generate(
                message,
                system_prompt=system_prompt,
                conversation_history=self.conversation_history[user_id],
                max_tokens=500,
                temperature=0.8
            )
            
            response_text = response.get('content', 'I encountered an error generating a response.')
            
            self.conversation_history[user_id].append({
                'role': 'assistant',
                'content': response_text
            })
            
            return response_text
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return f"Sorry, I encountered an error: {str(e)}"
    
    async def _analyze_text(self, text: str) -> str:
        """Analyze text using AI."""
        if not self.llm_provider:
            return "AI provider not configured."
        
        prompt = f"""Analyze the following text and provide insights:

Text: {text}

Provide:
1. Sentiment (positive/negative/neutral)
2. Key topics
3. Summary
4. Tone"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=300,
                temperature=0.5
            )
            
            return response.get('content', 'Analysis failed.')
            
        except Exception as e:
            logger.error(f"Error analyzing text: {e}")
            return f"Analysis error: {str(e)}"
    
    async def _translate_text(self, text: str, target_lang: str) -> str:
        """Translate text to target language."""
        if not self.llm_provider:
            return "AI provider not configured."
        
        prompt = f"Translate the following text to {target_lang}:\n\n{text}"
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=500,
                temperature=0.3
            )
            
            return response.get('content', 'Translation failed.')
            
        except Exception as e:
            logger.error(f"Error translating: {e}")
            return f"Translation error: {str(e)}"
    
    async def _generate_joke(self) -> str:
        """Generate a random joke."""
        if not self.llm_provider:
            return "Why did the AI cross the road? To get to the other dataset! 🤖"
        
        personality_joke_prompts = {
            'kawaii': "Tell a cute, wholesome joke in kawaii style with emojis!",
            'tsundere': "Tell a joke but act like you don't really want to tell it (tsundere style).",
            'playful': "Tell a fun, energetic joke with emojis!",
            'professional': "Tell a clean, professional joke.",
            'friendly': "Tell a friendly, light-hearted joke."
        }
        
        prompt = personality_joke_prompts.get(self.personality, personality_joke_prompts['friendly'])
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=200,
                temperature=0.9
            )
            
            return response.get('content', "I tried to think of a joke, but my humor module is buffering! 😅")
            
        except Exception as e:
            logger.error(f"Error generating joke: {e}")
            return "Why did the bot fail? Because it couldn't handle the async! 🤖"
    
    async def start(self):
        """Start the Discord bot."""
        try:
            await self.bot.start(self.token)
        except Exception as e:
            logger.error(f"Error starting Discord bot: {e}")
            raise
    
    async def stop(self):
        """Stop the Discord bot."""
        await self.bot.close()
    
    def run(self):
        """Run the Discord bot (blocking)."""
        try:
            self.bot.run(self.token)
        except Exception as e:
            logger.error(f"Error running Discord bot: {e}")
            raise


def create_discord_bot(token: str, llm_provider=None, personality: str = 'friendly') -> DiscordBotIntegration:
    """
    Create a Discord bot integration.
    
    Args:
        token: Discord bot token
        llm_provider: LLM provider for AI responses
        personality: Bot personality
    
    Returns:
        DiscordBotIntegration instance
    """
    return DiscordBotIntegration(token, llm_provider, personality)
