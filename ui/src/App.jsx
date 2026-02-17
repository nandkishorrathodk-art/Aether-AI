import React, { useState } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import {
  Box,
  IconButton,
  Drawer,
  Tabs,
  Tab,
  Badge,
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Chat as ChatIcon,
  Face as FaceIcon,
  Visibility as MonitorIcon,
  Lightbulb as SuggestionsIcon,
  CalendarToday as PlanIcon,
  Computer as ControlIcon,
  BugReport as BugBountyIcon,
  Assessment as ReportIcon,
  EmojiEmotions as PersonalityIcon,
} from '@mui/icons-material';
import JarvisDashboard from './components/JarvisDashboard';
import ChatInterface from './components/ChatInterface';
import Settings from './components/Settings';
import Notifications from './components/Notifications';
import CompactTaskBar from './components/CompactTaskBar';
import AnimeCharacter from './components/AnimeCharacter';
import MonitoringPanel from './components/v090/MonitoringPanel';
import ProactiveSuggestions from './components/v090/ProactiveSuggestions';
import DailyPlan from './components/v090/DailyPlan';
import PCControlPanel from './components/v090/PCControlPanel';
import BugBountyAutopilot from './components/v090/BugBountyAutopilot';
import DailyReport from './components/v090/DailyReport';
import PersonalitySettings from './components/v090/PersonalitySettings';

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
  const [showV090Panel, setShowV090Panel] = useState(false);
  const [v090Tab, setV090Tab] = useState(0);
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [newSuggestions, setNewSuggestions] = useState(0);
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

  const v090Panels = [
    { label: 'Monitor', icon: <MonitorIcon />, component: <MonitoringPanel /> },
    { label: 'Suggestions', icon: <SuggestionsIcon />, component: <ProactiveSuggestions />, badge: newSuggestions },
    { label: 'Daily Plan', icon: <PlanIcon />, component: <DailyPlan /> },
    { label: 'PC Control', icon: <ControlIcon />, component: <PCControlPanel /> },
    { label: 'Bug Bounty', icon: <BugBountyIcon />, component: <BugBountyAutopilot /> },
    { label: 'Report', icon: <ReportIcon />, component: <DailyReport /> },
    { label: 'Personality', icon: <PersonalityIcon />, component: <PersonalitySettings /> },
  ];

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
            onClick={() => setShowV090Panel(!showV090Panel)}
            sx={{
              backgroundColor: showV090Panel ? 'rgba(156, 39, 176, 0.2)' : 'rgba(0, 255, 255, 0.1)',
              border: showV090Panel ? '1px solid rgba(156, 39, 176, 0.5)' : '1px solid rgba(0, 255, 255, 0.3)',
              color: showV090Panel ? '#9c27b0' : '#00ffff',
              '&:hover': {
                backgroundColor: showV090Panel ? 'rgba(156, 39, 176, 0.3)' : 'rgba(0, 255, 255, 0.2)',
                boxShadow: showV090Panel ? '0 0 10px #9c27b0' : '0 0 10px #00ffff',
              },
            }}
          >
            <Badge badgeContent={newSuggestions} color="error">
              <SuggestionsIcon />
            </Badge>
          </IconButton>

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
          anchor="left"
          open={showV090Panel}
          onClose={() => setShowV090Panel(false)}
          PaperProps={{
            sx={{
              width: { xs: '100%', sm: 500, md: 600 },
              backgroundColor: 'rgba(0, 10, 20, 0.95)',
              backdropFilter: 'blur(10px)',
              borderRight: '1px solid rgba(156, 39, 176, 0.3)',
            },
          }}
        >
          <Box sx={{ p: 2 }}>
            <Tabs
              value={v090Tab}
              onChange={(e, newValue) => setV090Tab(newValue)}
              variant="scrollable"
              scrollButtons="auto"
              sx={{
                mb: 2,
                '& .MuiTab-root': {
                  color: 'rgba(255, 255, 255, 0.6)',
                  minWidth: 'auto',
                  px: 2,
                },
                '& .Mui-selected': {
                  color: '#9c27b0',
                },
                '& .MuiTabs-indicator': {
                  backgroundColor: '#9c27b0',
                  boxShadow: '0 0 10px #9c27b0',
                },
              }}
            >
              {v090Panels.map((panel, index) => (
                <Tab
                  key={index}
                  icon={
                    panel.badge ? (
                      <Badge badgeContent={panel.badge} color="error">
                        {panel.icon}
                      </Badge>
                    ) : (
                      panel.icon
                    )
                  }
                  label={panel.label}
                  iconPosition="start"
                />
              ))}
            </Tabs>
            <Box sx={{ maxHeight: 'calc(100vh - 120px)', overflow: 'auto' }}>
              {v090Panels[v090Tab]?.component}
            </Box>
          </Box>
        </Drawer>

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
