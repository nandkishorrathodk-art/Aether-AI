import React, { useState } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Box, IconButton, Drawer, Switch, FormControlLabel } from '@mui/material';
import SettingsIcon from '@mui/icons-material/Settings';
import ChatIcon from '@mui/icons-material/Chat';
import FaceIcon from '@mui/icons-material/Face';
import JarvisDashboard from './components/JarvisDashboard';
import ChatInterface from './components/ChatInterface';
import Settings from './components/Settings';
import Notifications from './components/Notifications';
import CompactTaskBar from './components/CompactTaskBar';
import AnimeCharacter from './components/AnimeCharacter';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00ffff',
    },
    secondary: {
      main: '#00ccff',
    },
    background: {
      default: '#000000',
      paper: 'rgba(0, 50, 50, 0.3)',
    },
    text: {
      primary: '#00ffff',
      secondary: '#00cccc',
    },
  },
  typography: {
    fontFamily: '"Courier New", monospace',
  },
});

function App() {
  const [showChat, setShowChat] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showAnimeCharacter, setShowAnimeCharacter] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [activeTasks, setActiveTasks] = useState([
    { name: 'Voice Recognition', status: 'idle' },
    { name: 'LLM Processing', status: 'idle' },
    { name: 'Memory System', status: 'running' },
  ]);

  const handleVoiceCommand = async (command) => {
    console.log('Voice command:', command);
    setIsListening(command === 'start');
    addNotification('Voice detection started', 'info');
    
    if (command === 'start') {
      setTimeout(() => {
        setIsListening(false);
        setIsSpeaking(true);
        setTimeout(() => setIsSpeaking(false), 2000);
      }, 3000);
    }
  };

  const addNotification = (message, type = 'info') => {
    const newNotification = {
      id: Date.now(),
      message,
      type,
    };
    setNotifications([...notifications, newNotification]);
    setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== newNotification.id));
    }, 5000);
  };

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Box sx={{ width: '100vw', height: '100vh', position: 'relative' }}>
        <JarvisDashboard onVoiceCommand={handleVoiceCommand} />

        <Box
          sx={{
            position: 'fixed',
            top: 10,
            right: 10,
            display: 'flex',
            gap: 1,
            zIndex: 100,
          }}
        >
          <IconButton
            onClick={() => setShowChat(!showChat)}
            sx={{
              backgroundColor: 'rgba(0, 255, 255, 0.1)',
              border: '1px solid rgba(0, 255, 255, 0.3)',
              color: '#00ffff',
              '&:hover': {
                backgroundColor: 'rgba(0, 255, 255, 0.2)',
                boxShadow: '0 0 10px #00ffff',
              },
            }}
          >
            <ChatIcon />
          </IconButton>

          <IconButton
            onClick={() => setShowSettings(!showSettings)}
            sx={{
              backgroundColor: 'rgba(0, 255, 255, 0.1)',
              border: '1px solid rgba(0, 255, 255, 0.3)',
              color: '#00ffff',
              '&:hover': {
                backgroundColor: 'rgba(0, 255, 255, 0.2)',
                boxShadow: '0 0 10px #00ffff',
              },
            }}
          >
            <SettingsIcon />
          </IconButton>

          <IconButton
            onClick={() => setShowAnimeCharacter(!showAnimeCharacter)}
            sx={{
              backgroundColor: showAnimeCharacter ? 'rgba(255, 105, 180, 0.2)' : 'rgba(0, 255, 255, 0.1)',
              border: showAnimeCharacter ? '1px solid rgba(255, 105, 180, 0.5)' : '1px solid rgba(0, 255, 255, 0.3)',
              color: showAnimeCharacter ? '#ff69b4' : '#00ffff',
              '&:hover': {
                backgroundColor: showAnimeCharacter ? 'rgba(255, 105, 180, 0.3)' : 'rgba(0, 255, 255, 0.2)',
                boxShadow: showAnimeCharacter ? '0 0 10px #ff69b4' : '0 0 10px #00ffff',
              },
            }}
          >
            <FaceIcon />
          </IconButton>
        </Box>

        <Drawer
          anchor="right"
          open={showChat}
          onClose={() => setShowChat(false)}
          PaperProps={{
            sx: {
              width: { xs: '100%', sm: 400 },
              backgroundColor: 'rgba(0, 20, 20, 0.95)',
              backdropFilter: 'blur(10px)',
              borderLeft: '1px solid rgba(0, 255, 255, 0.3)',
            },
          }}
        >
          <ChatInterface onClose={() => setShowChat(false)} />
        </Drawer>

        <Drawer
          anchor="right"
          open={showSettings}
          onClose={() => setShowSettings(false)}
          PaperProps={{
            sx: {
              width: { xs: '100%', sm: 400 },
              backgroundColor: 'rgba(0, 20, 20, 0.95)',
              backdropFilter: 'blur(10px)',
              borderLeft: '1px solid rgba(0, 255, 255, 0.3)',
            },
          }}
        >
          <Settings onClose={() => setShowSettings(false)} />
        </Drawer>

        <Notifications notifications={notifications} />

        <CompactTaskBar tasks={activeTasks} />

        {showAnimeCharacter && (
          <AnimeCharacter 
            isListening={isListening}
            isSpeaking={isSpeaking}
            mood="neutral"
          />
        )}
      </Box>
    </ThemeProvider>
  );
}

export default App;
