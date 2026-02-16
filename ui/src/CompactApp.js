import React, { useState } from 'react';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import FloatingDashboard from './FloatingDashboard';
import ChatInterface from './components/ChatInterface';
import VoiceControl from './components/VoiceControl';
import Settings from './components/Settings';
import Notifications from './components/Notifications';
import './App.css';

// Compact dark theme with glassmorphism
const compactTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#6366f1',
      light: '#818cf8',
      dark: '#4f46e5',
    },
    secondary: {
      main: '#8b5cf6',
    },
    background: {
      default: 'transparent',
      paper: 'rgba(30, 41, 59, 0.8)',
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    fontSize: 13, // Slightly smaller for compact UI
  },
  shape: {
    borderRadius: 12,
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backdropFilter: 'blur(10px)',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 600,
        },
      },
    },
  },
});

function CompactApp() {
  const [sessionId] = useState(() => `session_${Date.now()}`);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [error, setError] = useState(null);

  const handleVoiceTranscription = (text, confidence) => {
    console.log(`Voice: "${text}" (${confidence}%)`);
  };

  return (
    <ThemeProvider theme={compactTheme}>
      <CssBaseline />
      <div style={{ 
        width: '100vw', 
        height: '100vh', 
        overflow: 'hidden',
        background: 'transparent' 
      }}>
        <FloatingDashboard>
          <ChatInterface 
            sessionId={sessionId} 
            onError={setError}
            onSettingsClick={() => setSettingsOpen(true)}
            compact={true}
          />
          <Settings 
            open={settingsOpen} 
            onClose={() => setSettingsOpen(false)} 
          />
          <Notifications />
        </FloatingDashboard>
      </div>
    </ThemeProvider>
  );
}

export default CompactApp;
