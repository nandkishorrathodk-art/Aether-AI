import React, { useState, useEffect, useRef } from 'react';
import { Box, Fade, Typography, ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import { Mic, MicOff, GraphicEq } from '@mui/icons-material';
import voiceService from './services/voiceService';
import './FloatingOrb.css';

const orbTheme = createTheme({
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
      paper: 'transparent',
    },
  },
});

const FloatingOrb = () => {
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [status, setStatus] = useState('idle');
  const [audioLevel, setAudioLevel] = useState(0);
  const [position, setPosition] = useState({ x: 20, y: 60 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStartRef = useRef({ x: 0, y: 0 });
  const dragDistanceRef = useRef(0);
  const isRecordingRef = useRef(false);
  const mediaRecorderRef = useRef(null);
  const streamRef = useRef(null);
  const shouldProcessAudioRef = useRef(true);
  const recordingIntervalRef = useRef(null);
  const recordingTimeoutRef = useRef(null);
  const audioContextRef = useRef(null);
  const analyserRef = useRef(null);
  const hasSignificantAudioRef = useRef(false);

  useEffect(() => {
    console.log('[AETHER] FloatingOrb component mounted');
    
    if (!window.electron) {
      setStatus('browser');
      return;
    }

    const playWelcome = async () => {
      console.log('🎤 [AETHER] Starting welcome sequence...');
      setIsSpeaking(true);
      setStatus('speaking');
      
      try {
        console.log('🔊 [AETHER] Speaking welcome message...');
        await voiceService.speak('At your service, boss!', {
          voice: 'female',
          speed: 1.0,
          play: true
        });
        
        console.log('⏳ [AETHER] Welcome complete, waiting 2500ms...');
        await new Promise(resolve => setTimeout(resolve, 2500));
      } catch (error) {
        console.error('❌ [AETHER] TTS failed:', error);
      }
      
      console.log('🎤 [AETHER] Now starting microphone...');
      setIsSpeaking(false);
      setStatus('listening');
      isRecordingRef.current = false;
      
      try {
        await startContinuousListening();
        console.log('✅ [AETHER] Microphone started successfully!');
      } catch (error) {
        console.error('❌ [AETHER] Microphone failed:', error);
      }
    };

    setTimeout(playWelcome, 1000);
  }, []);

  const toggleMute = () => {
    if (!window.electron) return;
    
    const newMutedState = !isMuted;
    
    if (newMutedState) {
      console.log('[DEBUG] Muting Aether - Setting all states');
      
      // Set states FIRST before cleanup
      setIsMuted(true);
      setIsListening(false);
      setIsSpeaking(false);
      setStatus('muted');
      setAudioLevel(0);
      
      if (recordingIntervalRef.current) {
        clearInterval(recordingIntervalRef.current);
        recordingIntervalRef.current = null;
      }
      if (recordingTimeoutRef.current) {
        clearTimeout(recordingTimeoutRef.current);
        recordingTimeoutRef.current = null;
      }
      
      if (voiceService.currentAudio) {
        voiceService.currentAudio.pause();
        voiceService.currentAudio = null;
      }
      
      shouldProcessAudioRef.current = false;
      if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
        mediaRecorderRef.current.stop();
      }
      if (audioContextRef.current) {
        try {
          audioContextRef.current.close();
        } catch (e) {
          console.log('[DEBUG] AudioContext already closed');
        }
        audioContextRef.current = null;
        analyserRef.current = null;
      }
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(track => track.stop());
        streamRef.current = null;
      }
      
      shouldProcessAudioRef.current = true;
      console.log('[DEBUG] Mute complete - isMuted: true');
    } else {
      console.log('[DEBUG] Unmuting Aether');
      setIsMuted(false);
      setStatus('listening');
      setIsListening(false);
      setIsSpeaking(false);
      startContinuousListening();
    }
  };

  const startContinuousListening = async () => {
    console.log(`🎙️ [MIC] startContinuousListening called - isRecording: ${isRecordingRef.current}`);
    
    if (isRecordingRef.current) {
      console.log('❌ [MIC] Already recording, ignoring duplicate call');
      return;
    }
    
    console.log('🧹 [MIC] Cleaning up old resources...');
    
    if (recordingIntervalRef.current) {
      clearInterval(recordingIntervalRef.current);
      recordingIntervalRef.current = null;
    }
    if (recordingTimeoutRef.current) {
      clearTimeout(recordingTimeoutRef.current);
      recordingTimeoutRef.current = null;
    }
    
    if (mediaRecorderRef.current) {
      try {
        if (mediaRecorderRef.current.state !== 'inactive') {
          mediaRecorderRef.current.stop();
        }
      } catch (e) {
        console.log('[MIC] MediaRecorder already stopped');
      }
      mediaRecorderRef.current = null;
    }
    
    if (audioContextRef.current) {
      try {
        audioContextRef.current.close();
      } catch (e) {
        console.log('[MIC] AudioContext already closed');
      }
      audioContextRef.current = null;
      analyserRef.current = null;
    }
    
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(track => track.stop());
      streamRef.current = null;
    }
    
    console.log('✅ [MIC] Setting isRecordingRef = true, requesting mic...');
    isRecordingRef.current = true;
    setIsListening(true);
    
    try {
      console.log('🎤 [MIC] Requesting getUserMedia...');
      const stream = await navigator.mediaDevices.getUserMedia({ 
        audio: {
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true
        }
      });
      console.log('✅ [MIC] Got stream, creating MediaRecorder...');
      streamRef.current = stream;
      
      const mediaRecorder = new MediaRecorder(stream);
      console.log('✅ [MIC] MediaRecorder created');
      mediaRecorderRef.current = mediaRecorder;
      const audioChunks = [];
      
      // Setup audio analysis for voice activity detection
      const audioContext = new (window.AudioContext || window.webkitAudioContext)();
      audioContextRef.current = audioContext;
      const source = audioContext.createMediaStreamSource(stream);
      const analyser = audioContext.createAnalyser();
      analyser.fftSize = 2048;
      analyser.smoothingTimeConstant = 0.8;
      source.connect(analyser);
      analyserRef.current = analyser;
      hasSignificantAudioRef.current = false;
      
      mediaRecorder.ondataavailable = (event) => {
        audioChunks.push(event.data);
      };
      
      mediaRecorder.onstop = async () => {
        console.log(`[DEBUG] mediaRecorder.onstop fired - shouldProcess: ${shouldProcessAudioRef.current}, audioChunks: ${audioChunks.length}, isRecording: ${isRecordingRef.current}`);
        
        // Prevent duplicate processing
        if (isRecordingRef.current === false) {
          console.log('[DEBUG] Already processed or stopped, ignoring duplicate onstop');
          return;
        }
        
        // Check if we should process this audio (not a forced stop for TTS)
        if (!shouldProcessAudioRef.current) {
          console.log('[DEBUG] Skipping audio processing (forced stop for TTS)');
          shouldProcessAudioRef.current = true;
          isRecordingRef.current = false;
          return;
        }
        
        if (audioChunks.length === 0) {
          console.log('[DEBUG] No audio chunks recorded, skipping');
          isRecordingRef.current = false;
          if (!isMuted) {
            setTimeout(() => {
              isRecordingRef.current = false;
              startContinuousListening();
            }, 1500);
          }
          return;
        }
        
        // Create audio blob (use recorded format, not force WAV)
        const audioBlob = new Blob(audioChunks, { type: mediaRecorder.mimeType || 'audio/webm' });
        console.log(`[DEBUG] Created audio blob, size: ${audioBlob.size} bytes, type: ${audioBlob.type}`);
        
        // Check if significant audio was detected during recording
        if (!hasSignificantAudioRef.current) {
          console.log('[DEBUG] No significant audio detected (no voice activity), skipping transcription');
          if (!isMuted) {
            setTimeout(() => {
              isRecordingRef.current = false;
              startContinuousListening();
            }, 1500);
          } else {
            isRecordingRef.current = false;
          }
          return;
        }
        
        // Skip if audio is too small (likely silence or system noise)
        // With echo cancellation + noise suppression, require larger size
        // Typical clear human speech for 3 seconds should be 25-30KB+
        if (audioBlob.size < 25000) {
          console.log(`[DEBUG] Audio too small (${audioBlob.size} bytes), skipping transcription`);
          if (!isMuted) {
            setTimeout(() => {
              isRecordingRef.current = false;
              startContinuousListening();
            }, 1500);
          } else {
            isRecordingRef.current = false;
          }
          return;
        }
        
        // Validate WebM blob by checking first few bytes (WebM signature: 0x1A45DFA3)
        try {
          const arrayBuffer = await audioBlob.slice(0, 100).arrayBuffer();
          const bytes = new Uint8Array(arrayBuffer);
          
          // Check for WebM/Matroska EBML header (0x1A 0x45 0xDF 0xA3)
          let hasValidHeader = false;
          for (let i = 0; i < Math.min(20, bytes.length - 4); i++) {
            if (bytes[i] === 0x1A && bytes[i+1] === 0x45 && bytes[i+2] === 0xDF && bytes[i+3] === 0xA3) {
              hasValidHeader = true;
              break;
            }
          }
          
          if (!hasValidHeader) {
            console.log('[DEBUG] Invalid WebM header detected, skipping corrupted blob');
            if (!isMuted) {
              setTimeout(() => {
                isRecordingRef.current = false;
                startContinuousListening();
              }, 1500);
            } else {
              isRecordingRef.current = false;
            }
            return;
          }
        } catch (validationError) {
          console.error('[DEBUG] Failed to validate audio blob:', validationError);
        }
        
        // Mark as not recording IMMEDIATELY to prevent duplicate requests
        console.log('[DEBUG] Setting isRecordingRef = false to prevent duplicates');
        isRecordingRef.current = false;
        
        // Send to backend for transcription
        try {
          console.log('[DEBUG] Sending audio for transcription...');
          const transcription = await voiceService.transcribe(audioBlob, { 
            language: 'en',
            model: 'base'
          });
          console.log('Transcription received:', transcription);
          
          // Show response
          console.log('[DEBUG] Checking transcription:', transcription);
          if (transcription && transcription.text && transcription.text.trim().length > 0) {
            console.log('[DEBUG] Transcription text found:', transcription.text);
            console.log('[DEBUG] Getting AI response...');
            setStatus('thinking');
            
            try {
              const API_BASE = 'http://localhost:8000';
              const chatResponse = await fetch(`${API_BASE}/api/v1/chat/conversation`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  message: transcription.text,
                  session_id: 'voice-session',
                  use_context: true,
                  stream: false,
                  temperature: 0.7,
                  max_tokens: 2048
                })
              });

              if (!chatResponse.ok) {
                throw new Error(`Chat API failed: ${chatResponse.statusText}`);
              }

              const chatData = await chatResponse.json();
              console.log('[DEBUG] Full conversation response:', chatData);
              const aiResponse = chatData.content || "Sorry, I didn't get a response.";
              console.log('[DEBUG] AI Response:', aiResponse);
              console.log('[DEBUG] Intent detected:', chatData.intent);
              
              console.log('[DEBUG] Setting speaking status...');
              
              // Stop recording to prevent feedback loop
              shouldProcessAudioRef.current = false;
              
              if (recordingIntervalRef.current) {
                clearInterval(recordingIntervalRef.current);
                recordingIntervalRef.current = null;
              }
              if (recordingTimeoutRef.current) {
                clearTimeout(recordingTimeoutRef.current);
                recordingTimeoutRef.current = null;
              }
              
              if (mediaRecorderRef.current && mediaRecorderRef.current.state === 'recording') {
                console.log('[DEBUG] Stopping recording to prevent audio feedback');
                mediaRecorderRef.current.stop();
              }
              if (streamRef.current) {
                streamRef.current.getTracks().forEach(track => track.stop());
                streamRef.current = null;
              }
              
              setStatus('speaking');
              setIsSpeaking(true);
              setIsListening(false);
              
              console.log('[DEBUG] About to call voiceService.speak():', aiResponse);
              
              console.log('[DEBUG] Calling speak...');
              await voiceService.speak(aiResponse, {
                voice: 'female',
                speed: 1.0,
                play: true
              });
              console.log('[DEBUG] Speech completed successfully');
              
              await new Promise(resolve => setTimeout(resolve, 1500));
            } catch (speakError) {
              console.error('[ERROR] AI/Speech error:', speakError);
              const errorMsg = "Sorry, I encountered an error.";
              await voiceService.speak(errorMsg, {
                voice: 'female',
                speed: 1.0,
                play: true
              });
            } finally {
              console.log('[DEBUG] Resetting state, restarting listening...');
              setIsSpeaking(false);
              
              if (!isMuted) {
                setStatus('listening');
                setTimeout(() => {
                  startContinuousListening();
                }, 1500);
              } else {
                setStatus('muted');
              }
              console.log('[DEBUG] State reset complete');
            }
          } else {
            console.warn('[WARN] No transcription text received:', transcription);
            if (!isMuted) {
              setTimeout(() => {
                startContinuousListening();
              }, 1500);
            }
          }
        } catch (error) {
          console.error('Transcription failed:', error);
          if (!isMuted) {
            setStatus('listening');
            setTimeout(() => {
              startContinuousListening();
            }, 1500);
          } else {
            setStatus('muted');
            setIsListening(false);
          }
        }
      };

      // Start recording
      console.log('▶️ [MIC] Starting MediaRecorder...');
      mediaRecorder.start();
      console.log('✅ [MIC] Recording started! Listening for 3s chunks...');
      
      // Monitor real audio levels and detect voice activity
      const dataArray = new Uint8Array(analyser.frequencyBinCount);
      recordingIntervalRef.current = setInterval(() => {
        analyser.getByteFrequencyData(dataArray);
        
        // Calculate average volume
        const sum = dataArray.reduce((a, b) => a + b, 0);
        const average = sum / dataArray.length;
        
        // Voice frequency range (85Hz - 255Hz is typical for human speech)
        const voiceRange = dataArray.slice(10, 30);
        const voiceSum = voiceRange.reduce((a, b) => a + b, 0);
        const voiceAverage = voiceSum / voiceRange.length;
        
        setAudioLevel(average);
        
        // Detect significant audio (likely speech, not background noise)
        // Require stronger signal: voice average > 50 and overall > 35
        // This filters out distant/background audio better
        if (voiceAverage > 50 && average > 35) {
          hasSignificantAudioRef.current = true;
        }
      }, 100);
      
      // Stop after 3 seconds (shorter = less chance of capturing silence)
      recordingTimeoutRef.current = setTimeout(() => {
        if (recordingIntervalRef.current) {
          clearInterval(recordingIntervalRef.current);
          recordingIntervalRef.current = null;
        }
        if (mediaRecorder.state === 'recording') {
          console.log('[DEBUG] Recording timeout, stopping mediaRecorder');
          mediaRecorder.stop();
        }
        setAudioLevel(0);
      }, 3000);
      
    } catch (error) {
      console.error('Microphone access denied:', error);
      setStatus('idle');
      setIsListening(false);
      isRecordingRef.current = false;
      
      // Speak error message
      await voiceService.speak('Microphone access denied. Please allow microphone permission.', {
        voice: 'female',
        speed: 1.0,
        play: true
      });
    }
  };

  const stopListening = () => {
    setAudioLevel(0);
    setIsListening(false);
    setStatus('idle');
    isRecordingRef.current = false;
  };

  const handleMouseDown = (e) => {
    setIsDragging(true);
    dragDistanceRef.current = 0;
    dragStartRef.current = {
      x: e.clientX - position.x,
      y: e.clientY - position.y,
      startX: e.clientX,
      startY: e.clientY
    };
    e.stopPropagation();
  };

  const handleMouseMove = (e) => {
    if (isDragging) {
      const deltaX = Math.abs(e.clientX - dragStartRef.current.startX);
      const deltaY = Math.abs(e.clientY - dragStartRef.current.startY);
      dragDistanceRef.current = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
      
      const newX = Math.max(0, Math.min(e.clientX - dragStartRef.current.x, window.innerWidth - 180));
      const newY = Math.max(0, Math.min(e.clientY - dragStartRef.current.y, window.innerHeight - 50));
      setPosition({ x: newX, y: newY });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleClick = (e) => {
    // Only toggle mute if we didn't drag (less than 5px movement)
    if (dragDistanceRef.current < 5) {
      toggleMute();
    }
  };

  useEffect(() => {
    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
      return () => {
        window.removeEventListener('mousemove', handleMouseMove);
        window.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isDragging, position]);

  const getOrbColor = () => {
    // Cyberpunk neon colors
    if (status === 'speaking') return 'linear-gradient(135deg, #ff00ff 0%, #00ffff 100%)';
    if (status === 'listening') return 'linear-gradient(135deg, #00ffff 0%, #ff00ff 100%)';
    if (status === 'thinking') return 'linear-gradient(135deg, #ffff00 0%, #ff00ff 100%)';
    if (status === 'muted') return 'linear-gradient(135deg, #555555 0%, #333333 100%)';
    if (status === 'browser') return 'linear-gradient(135deg, #ff0000 0%, #ff6600 100%)';
    return 'linear-gradient(135deg, #00ffff 0%, #0099ff 100%)';
  };

  const getGlowIntensity = () => {
    if (status === 'listening') return audioLevel / 2;
    if (status === 'speaking') return 60;
    if (status === 'thinking') return 40;
    return 20;
  };

  if (status === 'browser') {
    return (
      <ThemeProvider theme={orbTheme}>
        <CssBaseline />
        <Box className="floating-orb-container">
          <Box className="error-message">
            <Typography variant="h6" color="error">
              ⚠️ Browser Not Supported
            </Typography>
            <Typography variant="caption">
              Desktop Electron only
            </Typography>
          </Box>
        </Box>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={orbTheme}>
      <CssBaseline />
      <Box 
        sx={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100vw',
          height: '100vh',
          pointerEvents: 'none',
          zIndex: 999999
        }}
      >
        <Box
          onMouseDown={handleMouseDown}
          sx={{
            position: 'absolute',
            left: `${position.x}px`,
            top: `${position.y}px`,
            pointerEvents: 'auto',
            cursor: isDragging ? 'grabbing' : 'grab',
            transition: isDragging ? 'none' : 'all 0.3s ease'
          }}
        >
        
        {/* Main Compact Widget */}
        <Box 
          className={`floating-widget ${status}`}
          onClick={handleClick}
          sx={{
            width: '160px',
            height: '40px',
            borderRadius: '20px',
            background: getOrbColor(),
            boxShadow: status === 'listening' ? `0 0 15px rgba(0, 255, 255, 0.8), 0 0 30px rgba(255, 0, 255, 0.4)` :
                       status === 'speaking' ? `0 0 15px rgba(255, 0, 255, 0.8), 0 0 30px rgba(0, 255, 255, 0.4)` :
                       `0 0 10px rgba(0, 255, 255, 0.6)`,
            cursor: isDragging ? 'grabbing' : 'grab',
            transition: isDragging ? 'none' : 'all 0.3s ease',
            position: 'relative',
            border: '2px solid rgba(0, 255, 255, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 12px',
            backdropFilter: 'blur(10px)',
            backgroundColor: 'rgba(0, 20, 40, 0.9)',
            zIndex: 1000000,
            '&:hover': {
              transform: 'scale(1.02)',
              boxShadow: status === 'listening' ? `0 0 20px rgba(0, 255, 255, 1), 0 0 40px rgba(255, 0, 255, 0.6)` :
                         status === 'speaking' ? `0 0 20px rgba(255, 0, 255, 1), 0 0 40px rgba(0, 255, 255, 0.6)` :
                         `0 0 15px rgba(0, 255, 255, 1)`,
            }
          }}
        >
          {/* Icon */}
          <Box sx={{ display: 'flex', alignItems: 'center', pointerEvents: 'none' }}>
            {status === 'muted' ? (
              <MicOff sx={{ fontSize: 20, color: '#666666' }} />
            ) : status === 'listening' ? (
              <GraphicEq className="pulse" sx={{ fontSize: 20, color: '#00ffff' }} />
            ) : status === 'speaking' ? (
              <Box sx={{ display: 'flex', gap: '2px', alignItems: 'center' }}>
                {[...Array(3)].map((_, i) => (
                  <Box key={i} sx={{ 
                    width: '3px', 
                    height: '12px',
                    background: '#ff00ff',
                    borderRadius: '2px',
                    animation: 'wave-bounce 0.6s ease-in-out infinite',
                    animationDelay: `${i * 0.15}s`
                  }} />
                ))}
              </Box>
            ) : (
              <Mic sx={{ fontSize: 20, color: '#00ffff' }} />
            )}
          </Box>

          {/* Status Text */}
          <Typography 
            variant="caption"
            sx={{
              color: status === 'listening' ? '#00ffff' : 
                     status === 'speaking' ? '#ff00ff' : 
                     status === 'thinking' ? '#ffff00' : 
                     status === 'muted' ? '#666666' : '#00ffff',
              fontWeight: 700,
              fontSize: '11px',
              textShadow: status === 'listening' ? '0 0 8px rgba(0,255,255,0.8)' :
                          status === 'speaking' ? '0 0 8px rgba(255,0,255,0.8)' :
                          '0 0 8px rgba(0,255,255,0.6)',
              pointerEvents: 'none',
              letterSpacing: '1px',
              textTransform: 'uppercase'
            }}
          >
            {status === 'listening' ? 'LISTENING' : 
             status === 'speaking' ? 'SPEAKING' : 
             status === 'thinking' ? 'THINKING' : 
             status === 'muted' ? 'MUTED' : 'IDLE'}
          </Typography>

          {/* Mini Visualizer */}
          {status === 'listening' && (
            <Box sx={{ display: 'flex', gap: '2px', alignItems: 'center', pointerEvents: 'none' }}>
              {[...Array(4)].map((_, i) => (
                <Box
                  key={i}
                  sx={{
                    width: '2px',
                    height: `${(audioLevel / 100) * 12 + 4}px`,
                    background: 'linear-gradient(to top, #00ffff, #ff00ff)',
                    borderRadius: '1px',
                    animation: 'bar-bounce 0.5s ease-in-out infinite',
                    animationDelay: `${i * 0.1}s`
                  }}
                />
              ))}
            </Box>
          )}
        </Box>

        </Box>
      </Box>
    </ThemeProvider>
  );
};

export default FloatingOrb;
