import React from 'react';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import VoiceOnlyDashboard from './VoiceOnlyDashboard';
import './App.css';

const voiceTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#6366f1',
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
  },
});

function VoiceApp() {
  return (
    <ThemeProvider theme={voiceTheme}>
      <CssBaseline />
      <div style={{ 
        width: '100vw', 
        height: '100vh', 
        overflow: 'hidden',
        background: 'transparent' 
      }}>
        <VoiceOnlyDashboard />
      </div>
    </ThemeProvider>
  );
}

export default VoiceApp;
