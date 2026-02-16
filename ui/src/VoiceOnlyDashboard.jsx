import React, { useState, useEffect } from 'react';
import { Box, IconButton, Tooltip, Fade, Typography, CircularProgress } from '@mui/material';
import {
  Mic,
  MicOff,
  VolumeUp,
  SettingsVoice,
  GraphicEq,
  Close,
  Minimize
} from '@mui/icons-material';
import voiceService from './services/voiceService';
import './VoiceOnlyDashboard.css';

const VoiceOnlyDashboard = () => {
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [response, setResponse] = useState('');
  const [audioLevel, setAudioLevel] = useState(0);

  const handleMinimize = () => {
    window.electron?.send('minimize-window');
  };

  const handleClose = () => {
    window.electron?.send('close-window');
  };

  const toggleListening = () => {
    setIsListening(!isListening);
    if (!isListening) {
      // Start voice recognition
      startVoiceRecognition();
    } else {
      // Stop voice recognition
      stopVoiceRecognition();
    }
  };

  const startVoiceRecognition = () => {
    console.log('Voice recognition started');
    // Simulate audio level animation
    const interval = setInterval(() => {
      setAudioLevel(Math.random() * 100);
    }, 100);
    
    // Cleanup
    setTimeout(() => clearInterval(interval), 5000);
  };

  const stopVoiceRecognition = () => {
    console.log('Voice recognition stopped');
    setAudioLevel(0);
  };

  useEffect(() => {
    // Welcome greeting on startup
    const playWelcomeGreeting = async () => {
      setIsSpeaking(true);
      setResponse('Hello sir, at your service! How may I help you today?');
      
      try {
        // Call TTS API using voiceService
        await voiceService.speak('Hello sir, at your service! How may I help you today?', {
          voice: 'male',
          speed: 1.0,
          play: true
        });
        
        console.log('✅ Welcome greeting played');
      } catch (error) {
        console.error('❌ TTS error:', error);
        // Fallback to browser TTS
        if ('speechSynthesis' in window) {
          const utterance = new SpeechSynthesisUtterance('Hello sir, at your service! How may I help you today?');
          utterance.rate = 1.0;
          utterance.pitch = 1.0;
          window.speechSynthesis.speak(utterance);
        }
      }
      
      // Clear response after 5 seconds
      setTimeout(() => {
        setIsSpeaking(false);
        setResponse('');
      }, 5000);
    };

    // Play greeting after 1 second
    setTimeout(() => {
      playWelcomeGreeting();
    }, 1000);

    // Auto-start listening after greeting (6 seconds total)
    setTimeout(() => {
      setIsListening(true);
      startVoiceRecognition();
    }, 6000);

    // Cleanup
    return () => {
      setIsListening(false);
      setIsSpeaking(false);
    };
  }, []);

  return (
    <Fade in timeout={500}>
      <Box className="voice-only-dashboard">
        {/* Drag Bar */}
        <Box className="voice-drag-bar" style={{ WebkitAppRegion: 'drag' }}>
          <Box className="voice-title">
            <SettingsVoice sx={{ mr: 1 }} />
            <Typography variant="subtitle2">Aether Voice</Typography>
          </Box>
          <Box className="voice-controls" style={{ WebkitAppRegion: 'no-drag' }}>
            <IconButton size="small" onClick={handleMinimize}>
              <Minimize fontSize="small" />
            </IconButton>
            <IconButton size="small" onClick={handleClose}>
              <Close fontSize="small" />
            </IconButton>
          </Box>
        </Box>

        {/* Main Voice Interface */}
        <Box className="voice-main">
          
          {/* Status Text */}
          <Typography 
            variant="h6" 
            className="voice-status"
            sx={{ 
              color: isListening ? '#6366f1' : '#94a3b8',
              fontWeight: 600,
              mb: 2
            }}
          >
            {isListening ? '🎤 Listening...' : '🎤 Tap to Speak'}
          </Typography>

          {/* Giant Mic Button */}
          <Box className="voice-button-container">
            <Box 
              className={`voice-ripple ${isListening ? 'active' : ''}`}
              sx={{ '--audio-level': audioLevel }}
            />
            <IconButton
              className={`giant-mic-button ${isListening ? 'listening' : ''}`}
              onClick={toggleListening}
              sx={{
                width: 180,
                height: 180,
                background: isListening 
                  ? 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)'
                  : 'linear-gradient(135deg, #334155 0%, #1e293b 100%)',
                '&:hover': {
                  transform: 'scale(1.05)',
                  boxShadow: isListening 
                    ? '0 0 60px rgba(99, 102, 241, 0.8)'
                    : '0 0 30px rgba(100, 100, 100, 0.5)'
                }
              }}
            >
              {isListening ? (
                <GraphicEq sx={{ fontSize: 80, color: 'white' }} />
              ) : (
                <Mic sx={{ fontSize: 80, color: '#94a3b8' }} />
              )}
            </IconButton>
          </Box>

          {/* Audio Visualizer */}
          {isListening && (
            <Box className="audio-visualizer">
              {[...Array(5)].map((_, i) => (
                <Box
                  key={i}
                  className="visualizer-bar"
                  sx={{
                    height: `${Math.random() * 60 + 20}%`,
                    animationDelay: `${i * 0.1}s`
                  }}
                />
              ))}
            </Box>
          )}

          {/* Transcript */}
          {transcript && (
            <Fade in>
              <Box className="voice-transcript glass-panel">
                <Typography variant="body2" color="textSecondary">
                  You said:
                </Typography>
                <Typography variant="body1" sx={{ mt: 1 }}>
                  "{transcript}"
                </Typography>
              </Box>
            </Fade>
          )}

          {/* Response */}
          {response && (
            <Fade in>
              <Box className="voice-response glass-panel">
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <VolumeUp sx={{ mr: 1, color: '#8b5cf6' }} />
                  <Typography variant="body2" color="textSecondary">
                    Aether:
                  </Typography>
                </Box>
                <Typography variant="body1">
                  {response}
                </Typography>
              </Box>
            </Fade>
          )}

          {/* Speaking Indicator */}
          {isSpeaking && (
            <Box className="speaking-indicator">
              <CircularProgress size={24} sx={{ color: '#8b5cf6', mr: 1 }} />
              <Typography variant="body2">Speaking...</Typography>
            </Box>
          )}

          {/* Instructions */}
          <Box className="voice-instructions">
            <Typography variant="caption" color="textSecondary">
              💡 Tip: Say "Aether" to activate
            </Typography>
            <Typography variant="caption" color="textSecondary">
              🎤 Press and hold Ctrl+Space anywhere
            </Typography>
          </Box>

        </Box>
      </Box>
    </Fade>
  );
};

export default VoiceOnlyDashboard;
