# n8n Workflow Examples for Aether AI

Ready-to-import n8n workflows for Aether AI integration.

## 📦 Available Workflows

### 1. **bug-bounty-automation.json**

Automated bug bounty scanning pipeline.

**Flow:**
```
Webhook → Start Scan → Check Success → Notify Slack → Respond
```

**How to use:**
1. Import into n8n
2. Activate workflow
3. Call webhook:
```bash
curl -X POST http://localhost:5678/webhook/bug-bounty-trigger \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "mode": "aggressive"
  }'
```

---

### 2. **ai-chatbot.json**

AI chatbot with voice response.

**Flow:**
```
Webhook → Chat AI → Generate TTS → Respond (Text + Audio)
```

**How to use:**
1. Import into n8n
2. Activate workflow
3. Call webhook:
```bash
curl -X POST http://localhost:5678/webhook/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Find XSS bugs in example.com",
    "user_id": "user123"
  }'
```

**Response:**
```json
{
  "text": "I'll start scanning example.com for XSS vulnerabilities...",
  "audio": "data:audio/mp3;base64,...",
  "intent": "security_scan",
  "session_id": "user123"
}
```

---

## 🚀 How to Import

1. Open n8n: `http://localhost:5678`
2. Click **"Workflows"** → **"Import from File"**
3. Select `.json` file
4. Click **"Import"**
5. **Activate** the workflow
6. Test with curl or Postman

---

## 🔧 Configuration

### Update Aether AI URL

If Aether is running on a different port/host, update in HTTP Request nodes:

```
http://localhost:8000/api/v1/n8n/webhook
```

### Add Slack/Discord Integration

1. Add Slack/Discord node
2. Connect to notification step
3. Configure webhook URL

---

## 📚 More Examples

See full documentation: [N8N_INTEGRATION.md](../N8N_INTEGRATION.md)

---

## ⚡ Quick Test

```bash
# Test bug bounty workflow
curl -X POST http://localhost:5678/webhook/bug-bounty-trigger \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Test chatbot
curl -X POST http://localhost:5678/webhook/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello Aether!"}'
```
