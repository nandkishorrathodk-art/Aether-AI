# 🔗 n8n Integration Guide for Aether AI

<div align="center">

**Connect Aether AI with 1000+ apps via n8n workflows!**

![n8n](https://img.shields.io/badge/n8n-EA4B71?style=for-the-badge&logo=n8n&logoColor=white)
![Aether AI](https://img.shields.io/badge/Aether_AI-00D9FF?style=for-the-badge)

Automate everything: Bug bounty workflows, AI chatbots, voice assistants, autonomous scans, and more!

</div>

---

## 📋 Table of Contents

- [What is n8n Integration?](#-what-is-n8n-integration)
- [Quick Start](#-quick-start)
- [Available Actions](#-available-actions)
- [Example Workflows](#-example-workflows)
- [API Reference](#-api-reference)
- [Best Practices](#-best-practices)

---

## 🎯 What is n8n Integration?

**n8n** is a powerful workflow automation tool (like Zapier but self-hosted). The Aether AI n8n integration allows you to:

✅ **Trigger Aether actions from n8n workflows**
- Send messages to AI chat
- Start autonomous security scans
- Analyze bug bounty programs
- Generate text with LLMs
- Transcribe audio
- Synthesize speech

✅ **Trigger n8n workflows from Aether AI**
- Send scan results to Slack/Discord
- Save findings to databases
- Create tickets in Jira
- Send emails/SMS notifications
- Update Google Sheets

---

## 🚀 Quick Start

### Step 1: Start Aether AI API

```bash
cd aether-ai-repo
venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

### Step 2: Install n8n

```bash
npm install -g n8n
n8n start
```

Access n8n at: `http://localhost:5678`

### Step 3: Create Your First Workflow

#### Example 1: AI Chat Bot

1. **Add Webhook node** (Trigger)
   - Method: `POST`
   - Path: `/chat-bot`

2. **Add HTTP Request node** (Aether AI)
   - Method: `POST`
   - URL: `http://localhost:8000/api/v1/n8n/webhook`
   - Body:
   ```json
   {
     "workflow_id": "chatbot-v1",
     "action": "chat",
     "data": {
       "message": "{{ $json.body.message }}",
       "session_id": "{{ $json.body.user_id }}"
     }
   }
   ```

3. **Add Respond to Webhook node**
   - Response: `{{ $json.data.response }}`

**Test it:**
```bash
curl -X POST http://localhost:5678/webhook/chat-bot \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello Aether!", "user_id": "user123"}'
```

---

## 🎬 Available Actions

### 1. **chat** - AI Conversation

Send messages to Aether's conversation engine.

**Request:**
```json
{
  "workflow_id": "my-workflow",
  "action": "chat",
  "data": {
    "message": "Find XSS bugs in example.com",
    "session_id": "session123"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "response": "I'll start scanning example.com for XSS vulnerabilities...",
    "intent": "security_scan",
    "session_id": "session123"
  }
}
```

---

### 2. **autonomous_scan** - Security Scanning

Start autonomous security scan on a target.

**Request:**
```json
{
  "workflow_id": "security-pipeline",
  "action": "autonomous_scan",
  "data": {
    "target": "https://example.com",
    "mode": "aggressive"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "session_id": "scan_abc123",
    "status": "started",
    "target": "https://example.com"
  }
}
```

---

### 3. **bug_bounty** - Program Analysis

Analyze bug bounty program details.

**Request:**
```json
{
  "workflow_id": "bounty-analyzer",
  "action": "bug_bounty",
  "data": {
    "program": "apple"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "program": "apple",
    "analysis": {
      "scope": ["*.apple.com"],
      "max_payout": 2000000,
      "vulnerabilities": ["XSS", "SQLi", "IDOR"]
    }
  }
}
```

---

### 4. **generate_text** - LLM Text Generation

Generate text using Aether's AI models.

**Request:**
```json
{
  "workflow_id": "content-generator",
  "action": "generate_text",
  "data": {
    "prompt": "Write a bug bounty report for XSS",
    "model": "auto",
    "temperature": 0.7,
    "max_tokens": 2048
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "text": "## XSS Vulnerability Report\n\n**Severity**: High\n...",
    "model": "gpt-4",
    "tokens": {
      "prompt": 12,
      "completion": 458,
      "total": 470
    }
  }
}
```

---

### 5. **transcribe_audio** - Speech to Text

Convert audio files to text.

**Request:**
```json
{
  "workflow_id": "voice-notes",
  "action": "transcribe_audio",
  "data": {
    "audio_url": "https://example.com/audio.wav"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "transcription": "This is a test audio file",
    "language": "en",
    "confidence": 0.95
  }
}
```

---

### 6. **synthesize_speech** - Text to Speech

Convert text to speech audio.

**Request:**
```json
{
  "workflow_id": "voice-alerts",
  "action": "synthesize_speech",
  "data": {
    "text": "Critical bug found!",
    "voice": "alloy",
    "speed": 1.0
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "audio_base64": "data:audio/mp3;base64,SUQzBAA...",
    "format": "mp3"
  }
}
```

---

## 💡 Example Workflows

### Workflow 1: Automated Bug Bounty Pipeline

```
Webhook (New Target)
  ↓
Aether: autonomous_scan
  ↓
Wait 5 minutes
  ↓
Aether: chat ("Get scan results")
  ↓
If bugs found:
  ├─→ Aether: generate_text (Create report)
  ├─→ Save to Google Sheets
  ├─→ Send to Slack
  └─→ Create Jira ticket
```

**n8n Workflow JSON:** (Import this)
```json
{
  "nodes": [
    {
      "name": "Webhook",
      "type": "n8n-nodes-base.webhook",
      "typeVersion": 1,
      "position": [250, 300],
      "parameters": {
        "path": "bug-bounty-trigger",
        "httpMethod": "POST"
      }
    },
    {
      "name": "Start Scan",
      "type": "n8n-nodes-base.httpRequest",
      "typeVersion": 1,
      "position": [450, 300],
      "parameters": {
        "url": "http://localhost:8000/api/v1/n8n/webhook",
        "method": "POST",
        "jsonParameters": true,
        "bodyParametersJson": "={\"workflow_id\": \"bounty-pipeline\", \"action\": \"autonomous_scan\", \"data\": {\"target\": \"{{ $json.body.target }}\", \"mode\": \"balanced\"}}"
      }
    },
    {
      "name": "Notify Slack",
      "type": "n8n-nodes-base.slack",
      "typeVersion": 1,
      "position": [650, 300],
      "parameters": {
        "channel": "#bug-bounty",
        "text": "Scan started: {{ $json.data.target }}"
      }
    }
  ],
  "connections": {
    "Webhook": {
      "main": [[{"node": "Start Scan", "type": "main", "index": 0}]]
    },
    "Start Scan": {
      "main": [[{"node": "Notify Slack", "type": "main", "index": 0}]]
    }
  }
}
```

---

### Workflow 2: AI Voice Assistant with Slack

```
Slack (Message Received)
  ↓
Aether: chat (Process message)
  ↓
Aether: synthesize_speech (Generate voice)
  ↓
Send audio to Slack thread
```

---

### Workflow 3: Scheduled Security Reports

```
Schedule (Every day 9 AM)
  ↓
Aether: chat ("Generate daily security report")
  ↓
Aether: generate_text (Format as markdown)
  ↓
Send email via Gmail
  ↓
Save to Google Drive
```

---

## 📖 API Reference

### POST `/api/v1/n8n/webhook`

**Trigger Aether AI actions from n8n.**

**Request Body:**
```json
{
  "workflow_id": "string",
  "action": "string",
  "data": {},
  "callback_url": "string (optional)",
  "async_mode": false
}
```

**Parameters:**
- `workflow_id` (required): Your n8n workflow ID
- `action` (required): Action to perform (see actions above)
- `data` (required): Action-specific data
- `callback_url` (optional): URL to receive results (for async)
- `async_mode` (optional): Run in background (default: false)

---

### POST `/api/v1/n8n/trigger`

**Trigger n8n workflows from Aether AI.**

**Request Body:**
```json
{
  "webhook_url": "string",
  "data": {},
  "method": "POST",
  "headers": {}
}
```

**Example:**
```bash
curl -X POST http://localhost:8000/api/v1/n8n/trigger \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "http://localhost:5678/webhook/my-workflow",
    "data": {
      "event": "bug_found",
      "severity": "critical",
      "target": "example.com"
    }
  }'
```

---

### GET `/api/v1/n8n/actions`

**List all available Aether actions.**

**Response:**
```json
{
  "actions": [
    {
      "name": "chat",
      "description": "Send message to conversation engine",
      "required_fields": ["message"],
      "optional_fields": ["session_id"]
    },
    ...
  ]
}
```

---

### GET `/api/v1/n8n/health`

**Health check endpoint.**

---

## ⚡ Best Practices

### 1. **Use Async Mode for Long Tasks**

```json
{
  "workflow_id": "long-scan",
  "action": "autonomous_scan",
  "data": {"target": "example.com"},
  "callback_url": "http://localhost:5678/webhook/scan-results",
  "async_mode": true
}
```

### 2. **Handle Errors Gracefully**

Add error handling in n8n workflows:
- Use "On Error" workflow
- Log failures to database
- Send alerts to monitoring systems

### 3. **Secure Your Webhooks**

- Use API keys in headers
- Whitelist IP addresses
- Enable HTTPS in production

### 4. **Rate Limiting**

Aether AI has built-in rate limiting. For high-volume workflows:
- Add delays between requests
- Use batch processing
- Cache results when possible

---

## 🔐 Security

### Authentication

Add authentication to n8n webhooks:

```json
{
  "webhook_url": "http://localhost:8000/api/v1/n8n/webhook",
  "headers": {
    "Authorization": "Bearer YOUR_API_KEY"
  }
}
```

### Environment Variables

Store sensitive data in n8n credentials:
- API keys
- Webhook URLs
- Database passwords

---

## 🐛 Troubleshooting

### Issue: "Connection refused"

**Solution:** Ensure Aether AI is running on `http://localhost:8000`

```bash
curl http://localhost:8000/health
```

### Issue: "Action not found"

**Solution:** Check available actions:

```bash
curl http://localhost:8000/api/v1/n8n/actions
```

### Issue: "Timeout error"

**Solution:** Use `async_mode: true` for long-running tasks.

---

## 📚 Resources

- [n8n Documentation](https://docs.n8n.io/)
- [n8n Community Workflows](https://n8n.io/workflows/)
- [Aether AI API Docs](http://localhost:8000/docs)

---

## 🎉 Example Use Cases

1. **Bug Bounty Automation**
   - Auto-scan new programs
   - Generate reports
   - Submit to platforms

2. **AI Customer Support**
   - Route tickets to Aether
   - Generate responses
   - Translate languages

3. **Content Generation**
   - Blog posts
   - Social media
   - Email campaigns

4. **Voice Assistants**
   - Transcribe calls
   - Generate responses
   - Synthesize replies

5. **Security Monitoring**
   - Scan websites
   - Analyze logs
   - Alert on threats

---

<div align="center">

**🚀 Start automating with Aether AI + n8n today!**

</div>
