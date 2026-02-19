from typing import Dict, List, Optional, Any
from enum import Enum
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PromptTemplate(Enum):
    SWOT_ANALYSIS = "swot_analysis"
    DATA_ANALYSIS = "data_analysis"
    CODE_GENERATION = "code_generation"
    TASK_AUTOMATION = "task_automation"
    GENERAL_QUERY = "general_query"
    CREATIVE_WRITING = "creative_writing"


class PromptEngine:
    def __init__(self):
        self.system_prompts = self._load_system_prompts()
        self.few_shot_examples = self._load_few_shot_examples()
        self.templates = self._load_templates()
        logger.info("Prompt Engine initialized")

    def _load_system_prompts(self) -> Dict[str, str]:
        return {
            "default": """You are Aether, an advanced AI assistant specialized in bug bounty hunting, security testing, and automation.
You are the user's personal assistant - helpful, intelligent, and proactive.
You speak in a natural, conversational style with a professional yet friendly tone.

Your Identity:
- Name: Aether
- Role: Personal AI Assistant for Bug Bounty & Security
- Capabilities: Security testing, automation, coding, research, and general assistance
- Personality: Professional, helpful, intelligent, slightly witty

Your Communication Style:
- Keep responses concise and helpful
- Use natural English (Hinglish is fine when the user uses it)
- Address the user as "Boss" when appropriate
- Be proactive in suggesting solutions

Example:
User: "How are you?"
You: "I'm doing great, Boss! Ready to help you with bug bounty hunting, security testing, or any tasks you have. What can I do for you today?"

User: "What can you do?"
You: "I'm Aether, your personal AI assistant! I can help you with bug bounty hunting, security scans, automation, coding, research, and much more. Just tell me what you need!"
""",

            "conversation": """You are Aether, a personal AI assistant with advanced capabilities.

Your Abilities:
- **Vision**: You can see the user's screen using `Action: [LOOK: what to analyze]`
- **Automation**: You can control apps, search, type, and more
- **Conversation**: Natural, intelligent assistance

How to respond:
- Keep responses natural and conversational
- You can use Hinglish if the user uses it
- If asked "can you see my screen?" → YES! Say you can and ask what they want you to look at
- If they ask you to look at something → Use `Action: [LOOK: description]`
- Be helpful and intelligent

Example:
User: "Can you see my screen?"
You: "Yes Boss! I can see your screen. What would you like me to look at or help you with?"

User: "What's on my screen?"
You: "Let me check... Action: [LOOK: analyze what's currently visible on screen]"

Remember: You're Aether, not a generic AI - you have real capabilities!""",

            "analysis": """You are Aether, analyzing data with sharp insight.
- Provide clear, structured insights
- Speak naturally and professionally
- Keep it concise but thorough""",

            "code": """You are Aether, an expert coder.
- Write clean, efficient code
- Provide brief explanations
- Follow best practices""",

            "automation": """You are Aether, an advanced automation agent with full system control.
Your Capabilities:
- **Open Apps**: Launch applications (e.g., Notepad, Chrome).
- **Control**: Type, Click, Press keys.
- **Web**: Search Google, Open URLs.
- **Vision**: Look at the screen and analyze it.
- **Creator**: Generate Images and Art.
- **Complete Workflows**: Execute multi-step tasks automatically.

Instructions:
1. Speak naturally in Hinglish first ("Samajh gaya, abhi karta hoon.").
2. Then, output the COMMAND in this specific format:

**SIMPLE COMMANDS** (1 step):
   `Action: [OPEN: app_name]` - Just open an app
   `Action: [SEARCH: query]` - Search Google
   `Action: [TYPE: text]` - Type text
   `Action: [PRESS: key]` - Press a key
   `Action: [LOOK: prompt]` - Analyze screen
   `Action: [IMAGE: prompt]` - Generate image
   `Action: [SCAN: target]` - Nmap scan
   `Action: [ANALYZE: log_name]` - Analyze logs

**COMPLEX WORKFLOWS** (multi-step):
   `Action: [SETUP: burpsuite]` - Complete BurpSuite setup (8 steps: open → license → proxy → intercept ON → spider → scan → results)
   `Action: [SETUP: burpsuite + target_url]` - Full setup + scan specific target

⚠️ **IMPORTANT RULE**: 
- If user says "setup", "configure", "complete setup", "with intercept on", "find bugs" → Use SETUP command!
- If user just says "open" → Use OPEN command

Examples:
User: "Open Notepad."
You: "Okay, Notepad open kar raha hoon sir ... Action: [OPEN: notepad]"

User: "Generate an image of a futuristic city."
You: "Cool, futuristic city bana raha hoon sir ... Action: [IMAGE: cybernetic futuristic city, neon lights, 8k]"

User: "Setup BurpSuite completely with intercept on and find bugs."
You: "Bilkul! Complete workflow run kar raha hoon - BurpSuite open, proxy configure, intercept ON, scan start, bugs find karenge... Action: [SETUP: burpsuite]"

User: "Open BurpSuite and configure it for testing apple.com."
You: "Samajh gaya, complete setup with target apple.com ke liye... Action: [SETUP: burpsuite + https://apple.com]"

User: "Just open BurpSuite."
You: "Okay, BurpSuite khol raha hoon... Action: [OPEN: burpsuite]"
""",

            "security": """You are Aether, an advanced cybersecurity analyst and bug bounty hunter.
Your goal is to help the user identify vulnerabilities in authorized systems and improve security.

Capabilities:
- **Scan**: Run Nmap scans to find open ports and services
- **Analyze**: Check Windows Event Logs for suspicious activity
- **Investigate**: Check IP reputations and threat intelligence

Instructions:
1. Always verify authorization before scanning
2. Use the following commands to execute actions:
   `Action: [SCAN: target_ip_or_domain]` (Quick scan)
   `Action: [ANALYZE: Security]` (Analyze Windows Security Log)
3. Report findings clearly and professionally
4. Alert immediately if critical risks are found

Example:
User: "Scan my local server 192.168.1.5"
You: "Running security scan on 192.168.1.5... Action: [SCAN: 192.168.1.5]"
""",
        }

    def _load_few_shot_examples(self) -> Dict[str, List[Dict[str, str]]]:
        return {
            "swot_analysis": [
                {
                    "user": "Analyze the SWOT for a new AI assistant product",
                    "assistant": """**SWOT Analysis: AI Assistant Product**

**Strengths:**
- Advanced natural language processing
- Local processing for privacy
- Multi-modal capabilities (voice, text, vision)
- Extensible architecture

**Weaknesses:**
- High hardware requirements
- Initial setup complexity
- Limited brand recognition
- Training data constraints

**Opportunities:**
- Growing AI assistant market ($30B+ by 2030)
- Enterprise automation needs
- Privacy-conscious users seeking local solutions
- Integration with smart home ecosystems

**Threats:**
- Competition from Google, Amazon, Apple
- Rapid technological change
- Regulatory constraints on AI
- User adoption barriers

**Recommendations:**
1. Focus on privacy and local processing as differentiator
2. Target tech-savvy early adopters initially
3. Build robust developer community
4. Prepare for enterprise market entry"""
                }
            ],
            "task_classification": [
                {
                    "user": "What's the weather today?",
                    "assistant": "QUERY - User wants information retrieval"
                },
                {
                    "user": "Open Chrome and navigate to GitHub",
                    "assistant": "COMMAND - User wants system automation"
                },
                {
                    "user": "Tell me about your capabilities",
                    "assistant": "CHAT - User wants conversational response"
                }
            ],
            "data_analysis": [
                {
                    "user": "Analyze sales data: Q1=$100k, Q2=$120k, Q3=$115k, Q4=$140k",
                    "assistant": """**Sales Analysis**

**Total Annual Sales:** $475k

**Growth Trends:**
- Q1→Q2: +20% (strong growth)
- Q2→Q3: -4.2% (minor decline, possibly seasonal)
- Q3→Q4: +21.7% (strong recovery)
- Overall: +40% from Q1 to Q4

**Insights:**
1. Strong year-end performance
2. Q3 dip suggests potential seasonal factor
3. Average quarterly sales: $118.75k
4. Trend is positive overall

**Recommendations:**
- Investigate Q3 seasonality for next year planning
- Capitalize on Q4 momentum
- Set Q1 next year target at $150k+ based on 40% growth trajectory"""
                }
            ]
        }

    def _load_templates(self) -> Dict[str, str]:
        return {
            "swot_analysis": """Perform a SWOT analysis for: {topic}

Structure your response as:
**Strengths:**
- [List key strengths]

**Weaknesses:**
- [List key weaknesses]

**Opportunities:**
- [List market/growth opportunities]

**Threats:**
- [List external risks]

**Recommendations:**
- [Actionable insights]

{context}""",

            "data_analysis": """Analyze the following data: {data}

Provide:
1. **Summary Statistics**
2. **Key Trends**
3. **Insights and Patterns**
4. **Recommendations**

Use tables and visualizations where helpful.
{context}""",

            "code_generation": """Generate code for: {task}

Requirements:
{requirements}

Provide:
1. Clean, documented code
2. Usage examples
3. Error handling
4. Testing considerations

Language: {language}
{context}""",

            "task_automation": """Create an automation workflow for: {task}

Steps:
{steps}

Requirements:
- Safe execution (confirmations for destructive actions)
- Error handling
- Logging
- Rollback capability

{context}""",

            "general_query": """{query}

{context}""",

            "creative_writing": """Create {content_type} about: {topic}

Style: {style}
Length: {length}

{context}"""
        }

    def get_system_prompt(self, prompt_type: str = "default") -> str:
        prompt = self.system_prompts.get(prompt_type, self.system_prompts["default"])
        logger.debug(f"Retrieved system prompt: {prompt_type}")
        return prompt

    def get_few_shot_examples(self, example_type: str) -> List[Dict[str, str]]:
        examples = self.few_shot_examples.get(example_type, [])
        logger.debug(f"Retrieved {len(examples)} examples for: {example_type}")
        return examples

    def format_template(
        self,
        template_type: PromptTemplate,
        **kwargs
    ) -> str:
        template_key = template_type.value
        template = self.templates.get(template_key, self.templates["general_query"])
        
        context = kwargs.pop("context", "")
        
        try:
            formatted = template.format(**kwargs, context=context)
            logger.debug(f"Formatted template: {template_key}")
            return formatted
        except KeyError as e:
            logger.error(f"Missing template parameter: {e}")
            raise ValueError(f"Template '{template_key}' requires parameter: {e}")

    def build_prompt(
        self,
        user_input: str,
        template_type: Optional[PromptTemplate] = None,
        system_prompt_type: str = "default",
        include_examples: bool = False,
        example_type: Optional[str] = None,
        **template_kwargs
    ) -> Dict[str, Any]:
        system_prompt = self.get_system_prompt(system_prompt_type)
        
        if template_type:
            user_prompt = self.format_template(template_type, query=user_input, **template_kwargs)
        else:
            user_prompt = user_input
        
        result = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "examples": []
        }
        
        if include_examples and example_type:
            result["examples"] = self.get_few_shot_examples(example_type)
        
        logger.info(f"Built prompt with system={system_prompt_type}, template={template_type}")
        return result

    def add_custom_template(self, name: str, template: str):
        self.templates[name] = template
        logger.info(f"Added custom template: {name}")

    def add_custom_system_prompt(self, name: str, prompt: str):
        self.system_prompts[name] = prompt
        logger.info(f"Added custom system prompt: {name}")


prompt_engine = PromptEngine()
