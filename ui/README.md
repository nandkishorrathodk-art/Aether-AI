# Aether AI - Desktop Application

Modern Electron-based desktop interface for the Aether AI assistant.

## Features

- **Chat Interface**: Beautiful Material-UI chat interface with conversation history
- **Voice Control**: Integrated voice input with real-time transcription
- **Settings Management**: Comprehensive settings for AI, voice, memory, and system
- **Cost Tracking**: Real-time cost monitoring for AI API usage
- **Keyboard Shortcuts**: Quick access with Ctrl+Space for voice input
- **System Tray**: Minimize to tray for background operation
- **Auto-Launch**: Optional startup with Windows

## Tech Stack

- **Frontend**: React 18 with Material-UI 5
- **Desktop**: Electron 28
- **State Management**: React Hooks
- **HTTP Client**: Axios with retry logic
- **WebSocket**: Socket.IO client for real-time updates
- **Testing**: Playwright for E2E tests

## Installation

```bash
cd ui
npm install
```

## Development

### Start React Development Server

```bash
npm run dev:react
```

### Start Electron App

```bash
npm start
```

### Development Mode (Both)

```bash
npm run dev
```

This will start both the React dev server and Electron app with hot-reload.

## Building

### Production Build

```bash
npm run build
```

### Package Electron App

```bash
npm run package
```

This creates a distributable Windows installer in the `dist/` directory.

## Testing

### Unit Tests (React Components)

```bash
npm test
```

### E2E Tests (Playwright)

```bash
npm run test:e2e
```

### E2E Tests with UI Mode

```bash
npm run test:e2e:ui
```

## Configuration

Create a `.env` file in the `ui/` directory:

```env
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=http://localhost:8000
```

## Keyboard Shortcuts

- **Ctrl+Space**: Activate voice input
- **Enter**: Send message (Shift+Enter for new line)
- **Escape**: Close settings/dialogs

## Project Structure

```
ui/
├── public/              # Static assets
├── src/
│   ├── components/      # React components
│   │   ├── ChatInterface.jsx
│   │   ├── VoiceControl.jsx
│   │   ├── Settings.jsx
│   │   └── Notifications.jsx
│   ├── services/        # API and service layer
│   │   └── api.js
│   ├── App.js           # Main application component
│   └── index.js         # React entry point
├── tests/
│   └── e2e/             # Playwright E2E tests
├── main.js              # Electron main process
├── preload.js           # Electron preload script
└── package.json
```

## Components

### ChatInterface

Main conversation UI with message history, AI provider display, and intent detection.

**Props:**
- `sessionId`: Current conversation session ID
- `onError`: Error callback function

### VoiceControl

Voice input button with recording visualization and audio level monitoring.

**Props:**
- `onTranscription`: Callback when transcription completes
- `onError`: Error callback function
- `enabled`: Enable/disable voice input

### Settings

Comprehensive settings drawer with tabs for General, Voice, AI, and Memory settings.

**Props:**
- `open`: Control drawer visibility
- `onClose`: Close callback function

### Notifications

Toast notification system for system events and errors.

## API Client

The `api.js` service provides methods for:

- **Chat**: `chat()`, `conversation()`, `getConversationHistory()`
- **Voice**: `transcribeAudio()`, `synthesizeSpeech()`, `getAudioDevices()`
- **Settings**: `getSettings()`, `updateSettings()`
- **Memory**: `rememberMemory()`, `recallMemory()`
- **WebSocket**: `connectWebSocket()`, `disconnectWebSocket()`

## IPC Communication

### Main → Renderer

- `toggle-voice-input`: Toggle voice input on/off
- `activate-voice-input`: Activate voice recording
- `show-notification`: Display notification

### Renderer → Main

- `minimize-to-tray`: Hide window to system tray
- `show-window`: Show window from tray
- `get-store-value`: Get persisted setting
- `set-store-value`: Save setting
- `set-auto-launch`: Configure auto-start

## Troubleshooting

### Backend Not Connected

Ensure the FastAPI backend is running:

```bash
cd ..
python -m venv venv
venv\Scripts\activate
python src/main.py
```

### Microphone Permission Denied

Check browser/system microphone permissions for Electron.

### Settings Not Persisting

Settings are stored in:
- **Backend Settings**: `data/settings.json`
- **Local Settings**: Electron Store in `%APPDATA%/aether-ai-ui`

### Build Errors

Clear cache and reinstall:

```bash
rm -rf node_modules package-lock.json
npm install
```

## Performance

- **Initial Load**: < 2 seconds
- **Message Response**: < 3 seconds (with backend)
- **Voice Transcription**: 1-2 seconds
- **Settings Load**: < 500ms

## License

MIT License - See LICENSE file for details
