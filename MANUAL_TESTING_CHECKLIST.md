# Manual Testing Checklist - Aether AI MVP v0.1.0

This checklist covers comprehensive manual testing for the MVP release of Aether AI.

## Test Environment Setup

- [ ] Python 3.12+ installed
- [ ] Virtual environment activated
- [ ] All dependencies installed via `requirements.txt`
- [ ] `.env` file configured with API keys
- [ ] FastAPI server starts without errors
- [ ] Electron UI launches successfully

## Core Components Testing

### 1. Voice Input Pipeline (STT)

#### Wake Word Detection
- [ ] Wake word "Jarvis" triggers detection (energy-based mode)
- [ ] Wake word detection works in noisy environment
- [ ] Wake word doesn't trigger on similar-sounding words
- [ ] Porcupine wake word detection works (if access key provided)
- [ ] Multiple wake words can be configured

#### Speech-to-Text
- [ ] Local Whisper model transcribes speech accurately (tiny/base/small models)
- [ ] OpenAI Whisper API transcribes speech accurately (if API key provided)
- [ ] Transcription works with clear speech (>90% accuracy)
- [ ] Transcription handles background noise gracefully
- [ ] Multi-language transcription works (English, Hindi, etc.)
- [ ] Silence detection auto-stops recording
- [ ] Real-time transcription completes in <3 seconds
- [ ] Audio device selection works correctly

### 2. Voice Output Pipeline (TTS)

#### Text-to-Speech Synthesis
- [ ] Local TTS (pyttsx3) generates natural-sounding speech
- [ ] OpenAI TTS generates high-quality voice (if API key provided)
- [ ] Voice selection works (male/female/neutral)
- [ ] Speed control adjusts playback rate correctly
- [ ] Volume control works as expected
- [ ] Audio playback is clear without distortion

#### TTS Caching
- [ ] Cached responses play in <50ms
- [ ] Cache hit rate improves over time (>50% after repeated phrases)
- [ ] Cache statistics are accurate
- [ ] Cache cleanup works when size limit exceeded

#### Output Queue Management
- [ ] Priority queue processes urgent messages first
- [ ] Background worker handles concurrent requests
- [ ] Queue statistics reflect actual usage
- [ ] Non-blocking playback mode works correctly

### 3. Conversation Engine

#### Intent Classification
- [ ] Query intents identified correctly (questions, information requests)
- [ ] Command intents identified correctly (actions, tasks)
- [ ] Analysis intents identified correctly (SWOT, data analysis)
- [ ] Code intents identified correctly (programming queries)
- [ ] Automation intents identified correctly (script execution)
- [ ] Creative intents identified correctly (idea generation)
- [ ] Chat intents identified correctly (casual conversation)

#### Context Management
- [ ] Multi-turn conversations maintain context correctly
- [ ] Conversation history persists across sessions
- [ ] Context truncation works when token limit exceeded
- [ ] Context compression reduces token usage effectively
- [ ] Session management creates/retrieves/deletes sessions correctly

#### LLM Integration (Multi-Provider)
- [ ] OpenAI provider works (GPT-4, GPT-3.5) with API key
- [ ] Anthropic provider works (Claude 3) with API key
- [ ] Google provider works (Gemini Pro) with API key
- [ ] Groq provider works (Llama 3, Mixtral) with API key
- [ ] Fireworks provider works with API key
- [ ] OpenRouter provider works with API key
- [ ] Intelligent routing selects appropriate provider per task
- [ ] Automatic fallback works when primary provider fails
- [ ] Cost tracking records spending accurately
- [ ] Streaming responses work correctly

### 4. Memory System

#### Vector Database (ChromaDB)
- [ ] Memories are stored with embeddings
- [ ] Semantic search returns relevant memories
- [ ] Memory deletion works correctly
- [ ] Collection management (create/get/delete) works
- [ ] Batch operations process multiple memories efficiently

#### Conversation History
- [ ] Messages are stored in SQLite database
- [ ] Important messages are embedded for RAG
- [ ] Session management works correctly
- [ ] RAG context retrieval returns relevant history
- [ ] Conversation statistics are accurate

#### User Profile
- [ ] Preferences are saved and loaded correctly
- [ ] Personal information persists across sessions
- [ ] Habits and patterns are learned over time
- [ ] Settings are updated correctly
- [ ] Multi-user support works (ProfileManager)

### 5. Automation Engine

#### Script Execution
- [ ] Python scripts execute successfully
- [ ] Batch files (.bat) execute on Windows
- [ ] Shell commands run correctly
- [ ] Timeout protection prevents hanging scripts
- [ ] Dangerous commands are blocked (del, rm, format, etc.)
- [ ] Safe commands execute without restrictions

#### GUI Control
- [ ] Mouse movement works correctly
- [ ] Mouse clicking works (left/right/middle)
- [ ] Keyboard typing works
- [ ] Key press simulation works
- [ ] Screenshots are captured correctly
- [ ] Image recognition finds UI elements (if configured)

#### File Operations
- [ ] File read/write works correctly
- [ ] File copy/move operations succeed
- [ ] Directory creation works
- [ ] File search with glob patterns works
- [ ] Dangerous paths are blocked (C:\Windows, system directories)
- [ ] File info includes MD5 hash

#### Window Management (Windows-specific)
- [ ] Get all windows lists open applications
- [ ] Get active window returns focused application
- [ ] Focus window switches to specified application
- [ ] Minimize/maximize/close window works correctly

### 6. API Endpoints (FastAPI)

#### Chat Endpoints
- [ ] POST `/api/v1/chat` generates responses
- [ ] GET `/api/v1/chat/providers` lists available providers
- [ ] GET `/api/v1/chat/cost-stats` returns accurate statistics
- [ ] POST `/api/v1/chat/conversation` processes conversations with context
- [ ] GET `/api/v1/chat/conversation/history/{session_id}` retrieves history
- [ ] DELETE `/api/v1/chat/conversation/session/{session_id}` clears session
- [ ] GET `/api/v1/chat/recommended-provider/{task_type}` suggests best provider

#### Voice Endpoints
- [ ] POST `/api/v1/voice/transcribe` transcribes uploaded audio
- [ ] POST `/api/v1/voice/transcribe-realtime` records and transcribes
- [ ] POST `/api/v1/voice/synthesize` generates audio file
- [ ] POST `/api/v1/voice/speak` synthesizes and plays audio
- [ ] GET `/api/v1/voice/devices` lists audio devices
- [ ] GET `/api/v1/voice/models` lists STT models
- [ ] GET `/api/v1/voice/tts/cache/stats` returns cache statistics

#### Memory Endpoints
- [ ] POST `/api/v1/memory/remember` stores memories
- [ ] POST `/api/v1/memory/recall` searches memories
- [ ] DELETE `/api/v1/memory/forget/{id}` deletes memory
- [ ] GET `/api/v1/memory/stats` returns memory statistics
- [ ] GET/PUT/DELETE `/api/v1/memory/profile/{user_id}` manages profiles

#### Settings Endpoints
- [ ] GET/PUT `/api/v1/settings/` retrieves/updates all settings
- [ ] POST `/api/v1/settings/reset` resets to defaults
- [ ] GET/PUT `/api/v1/settings/voice` manages voice settings
- [ ] GET/PUT `/api/v1/settings/ai` manages AI settings

### 7. Electron Desktop Application

#### UI Components
- [ ] Chat interface displays messages correctly
- [ ] Message bubbles show user/assistant avatars
- [ ] Intent chips display detected intent
- [ ] Cost tracking shows per-message costs
- [ ] Provider display shows current AI provider
- [ ] Voice control button triggers recording
- [ ] Audio level visualization animates during recording
- [ ] Settings drawer opens/closes smoothly
- [ ] Tabs in settings work correctly (General/Voice/AI/Memory)

#### System Integration
- [ ] System tray icon appears in taskbar
- [ ] Minimize to tray works
- [ ] Show/hide window from tray menu
- [ ] Auto-launch on startup works (if enabled)
- [ ] Global keyboard shortcut (Ctrl+Space) activates voice
- [ ] IPC communication with main process works

#### Notifications
- [ ] Toast notifications appear on events
- [ ] Auto-dismiss works after timeout
- [ ] Manual dismiss works on click

### 8. End-to-End Voice Pipeline

#### Full Voice Workflow
- [ ] Say wake word → Aether listens → speak command → AI responds → TTS plays
- [ ] Voice conversation maintains context across turns
- [ ] Session management tracks voice interactions
- [ ] Error handling speaks error messages to user
- [ ] Automatic retry on STT failures works
- [ ] Fallback from local to cloud STT works
- [ ] Response time <3 seconds average

#### Pipeline Performance
- [ ] Initialization completes in <20 seconds
- [ ] Memory usage stays <3GB during operation
- [ ] No memory leaks during extended use (1+ hour)
- [ ] CPU usage <50% average
- [ ] No crashes or hangs during normal operation

## Performance Testing

### Response Time
- [ ] Voice command to response: <3 seconds average
- [ ] API endpoint latency: <500ms average
- [ ] TTS cache hits: <50ms latency
- [ ] STT transcription: <1.5 seconds for 5-second audio

### Resource Usage
- [ ] RAM usage: <3GB peak
- [ ] CPU usage: <50% average, <80% peak
- [ ] Disk usage: <500MB for models and data
- [ ] Network usage: Reasonable for cloud API calls

### Scalability
- [ ] Handles 10+ consecutive voice commands without degradation
- [ ] Supports 100+ conversation history messages
- [ ] Vector database scales to 1000+ memories
- [ ] Cache supports 500+ TTS entries

## Security Testing

### Input Validation
- [ ] SQL injection attempts blocked (memory system)
- [ ] Path traversal attacks blocked (file operations)
- [ ] Command injection blocked (script executor)
- [ ] Dangerous system paths blocked

### API Security
- [ ] Rate limiting enforces 60 requests/minute
- [ ] CORS configured correctly for Electron frontend
- [ ] API keys not exposed in logs or responses
- [ ] Error messages don't leak sensitive information

### Data Privacy
- [ ] User data stored locally only (no unauthorized uploads)
- [ ] API keys stored securely in .env file
- [ ] Conversation history encrypted (if implemented)
- [ ] Memory embeddings contain no plaintext secrets

## Edge Cases and Error Handling

### Network Issues
- [ ] Graceful degradation when internet unavailable
- [ ] Retry logic works for transient failures
- [ ] Fallback to local models when cloud APIs fail
- [ ] User-friendly error messages for network errors

### Invalid Input
- [ ] Empty voice input handled gracefully
- [ ] Invalid audio formats rejected with helpful error
- [ ] Malformed API requests return 422 with details
- [ ] Out-of-range settings values rejected

### System Limits
- [ ] Conversation history truncates when token limit exceeded
- [ ] TTS cache clears oldest entries when full
- [ ] Vector database handles large memory collections
- [ ] Script execution timeout prevents hanging processes

## Cross-Platform Testing (Windows Focus)

### Windows-Specific Features
- [ ] PyAutoGUI works on Windows 10/11
- [ ] pywin32 window management works correctly
- [ ] Batch file execution works
- [ ] Audio devices detected correctly
- [ ] System tray integration works
- [ ] Auto-launch registry entry works

### Compatibility
- [ ] Works on Windows 10 (build 19041+)
- [ ] Works on Windows 11
- [ ] Intel Core Ultra 5/Ryzen 7 CPU compatible
- [ ] 8-16GB RAM sufficient for operation
- [ ] RTX 4070-class GPU optional (cloud-based AI)

## Installation and Deployment

### Installation
- [ ] `install.bat` completes without errors
- [ ] Virtual environment created correctly
- [ ] All dependencies installed successfully
- [ ] Desktop shortcut created
- [ ] .env file configuration prompted

### Startup
- [ ] `start-aether.bat` launches both backend and UI
- [ ] Backend server starts on http://localhost:8000
- [ ] Electron UI connects to backend correctly
- [ ] Logs generated in `/logs` directory

### Uninstallation
- [ ] `uninstall.bat` removes virtual environment
- [ ] Desktop shortcut removed
- [ ] Optional data removal works correctly
- [ ] User data preserved if selected

## Documentation Testing

### README.md
- [ ] Installation instructions accurate
- [ ] Quick start guide works
- [ ] Configuration section clear
- [ ] Troubleshooting section helpful

### API Documentation
- [ ] FastAPI auto-docs available at http://localhost:8000/docs
- [ ] All endpoints documented correctly
- [ ] Request/response schemas accurate
- [ ] Example requests work

### User Guides
- [ ] QUICKSTART.md easy to follow
- [ ] MULTI_PROVIDER_SETUP.md explains provider configuration
- [ ] VOICE_PIPELINE.md explains voice workflow
- [ ] TTS_GUIDE.md explains TTS configuration

## Test Results Summary

**Test Date**: _____________

**Tester**: _____________

**Total Tests**: ______

**Passed**: ______ (%_____)

**Failed**: ______ (%_____)

**Blocked**: ______ (%_____)

**Critical Issues Found**: ______

**Recommendations**:
- 
- 
- 

**Overall Assessment**: □ Ready for Release  □ Needs Fixes  □ Major Issues

---

**Notes**:
