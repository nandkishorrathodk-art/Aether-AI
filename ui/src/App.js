import React, { useState, useEffect } from 'react';
import {
  ThemeProvider,
  createTheme,
  CssBaseline,
  Box,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Tooltip,
  Badge,
  Chip,
} from '@mui/material';
import SettingsIcon from '@mui/icons-material/Settings';
import DeleteIcon from '@mui/icons-material/Delete';
import AttachMoneyIcon from '@mui/icons-material/AttachMoney';
import ChatInterface from './components/ChatInterface';
import VoiceControl from './components/VoiceControl';
import Settings from './components/Settings';
import Notifications from './components/Notifications';
import api from './services/api';
import './App.css';

const darkTheme = createTheme({
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
      default: '#0f172a',
      paper: '#1e293b',
    },
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
  },
  shape: {
    borderRadius: 8,
  },
});

function App() {
  const [sessionId] = useState(() => `session_${Date.now()}`);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(true);
  const [costStats, setCostStats] = useState(null);
  const [error, setError] = useState(null);
  const [backendStatus, setBackendStatus] = useState('checking');

  useEffect(() => {
    checkBackendStatus();
    loadCostStats();

    const interval = setInterval(loadCostStats, 60000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  const checkBackendStatus = async () => {
    try {
      await api.getProviders();
      setBackendStatus('connected');
    } catch (err) {
      setBackendStatus('disconnected');
      setError('Backend not connected. Please start the FastAPI server.');
    }
  };

  const loadCostStats = async () => {
    try {
      const stats = await api.getCostStats();
      setCostStats(stats);
    } catch (err) {
      console.error('Failed to load cost stats:', err);
    }
  };

  const handleVoiceTranscription = (text, confidence) => {
    console.log(`Voice transcription: "${text}" (confidence: ${confidence})`);
  };

  const handleClearSession = async () => {
    if (window.confirm('Clear conversation history?')) {
      try {
        await api.clearSession(sessionId);
        window.location.reload();
      } catch (err) {
        setError('Failed to clear session');
      }
    }
  };

  const getStatusColor = () => {
    if (backendStatus === 'connected') return 'success';
    if (backendStatus === 'disconnected') return 'error';
    return 'default';
  };

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
        <AppBar position="static" elevation={1}>
          <Toolbar>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
              <Box
                sx={{
                  width: 36,
                  height: 36,
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 'bold',
                  fontSize: 18,
                }}
              >
                A
              </Box>
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                AETHER AI
              </Typography>
              
              <Chip
                label={backendStatus === 'connected' ? 'Online' : backendStatus === 'disconnected' ? 'Offline' : 'Checking...'}
                color={getStatusColor()}
                size="small"
                sx={{ ml: 2 }}
              />
            </Box>

            {costStats && (
              <Tooltip title={`Today: $${costStats.today_cost?.toFixed(4) || '0.0000'} | Total: $${costStats.total_cost?.toFixed(4) || '0.0000'}`}>
                <Chip
                  icon={<AttachMoneyIcon />}
                  label={`$${costStats.today_cost?.toFixed(4) || '0.0000'}`}
                  size="small"
                  sx={{ mr: 1 }}
                />
              </Tooltip>
            )}

            <VoiceControl
              onTranscription={handleVoiceTranscription}
              onError={setError}
              enabled={voiceEnabled}
            />

            <Tooltip title="Clear conversation">
              <IconButton color="inherit" onClick={handleClearSession} sx={{ ml: 1 }}>
                <DeleteIcon />
              </IconButton>
            </Tooltip>

            <Tooltip title="Settings">
              <IconButton color="inherit" onClick={() => setSettingsOpen(true)}>
                <SettingsIcon />
              </IconButton>
            </Tooltip>
          </Toolbar>
        </AppBar>

        <Box sx={{ flex: 1, overflow: 'hidden' }}>
          <ChatInterface sessionId={sessionId} onError={setError} />
        </Box>

        {error && (
          <Box
            sx={{
              position: 'fixed',
              bottom: 16,
              left: '50%',
              transform: 'translateX(-50%)',
              zIndex: 9999,
            }}
          >
            <Chip
              label={error}
              color="error"
              onDelete={() => setError(null)}
              sx={{ maxWidth: 500 }}
            />
          </Box>
        )}

        <Settings open={settingsOpen} onClose={() => setSettingsOpen(false)} />
        <Notifications />
      </Box>
    </ThemeProvider>
  );
}

export default App;
