import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  IconButton,
  Tooltip,
  CircularProgress,
  Typography,
  Fade,
} from '@mui/material';
import MicIcon from '@mui/icons-material/Mic';
import MicOffIcon from '@mui/icons-material/MicOff';
import GraphicEqIcon from '@mui/icons-material/GraphicEq';
import api from '../services/api';

function VoiceControl({ onTranscription, onError, enabled = true }) {
  const [isRecording, setIsRecording] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [audioLevel, setAudioLevel] = useState(0);
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const animationFrameRef = useRef(null);
  const analyserRef = useRef(null);
  const streamRef = useRef(null);

  useEffect(() => {
    return () => {
      stopRecording();
    };
  }, []);

  useEffect(() => {
    if (isRecording) {
      startAudioLevelMonitoring();
    } else {
      stopAudioLevelMonitoring();
    }

    return () => stopAudioLevelMonitoring();
  }, [isRecording]);

  const startAudioLevelMonitoring = () => {
    if (!streamRef.current) return;

    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const analyser = audioContext.createAnalyser();
    const microphone = audioContext.createMediaStreamSource(streamRef.current);
    
    analyser.smoothingTimeConstant = 0.8;
    analyser.fftSize = 256;
    
    microphone.connect(analyser);
    analyserRef.current = analyser;

    const dataArray = new Uint8Array(analyser.frequencyBinCount);

    const updateLevel = () => {
      analyser.getByteFrequencyData(dataArray);
      const average = dataArray.reduce((a, b) => a + b) / dataArray.length;
      setAudioLevel(average / 255);
      animationFrameRef.current = requestAnimationFrame(updateLevel);
    };

    updateLevel();
  };

  const stopAudioLevelMonitoring = () => {
    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current);
      animationFrameRef.current = null;
    }
    setAudioLevel(0);
  };

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;

      const mediaRecorder = new MediaRecorder(stream, {
        mimeType: 'audio/webm',
      });

      mediaRecorderRef.current = mediaRecorder;
      audioChunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data);
        }
      };

      mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        await processAudio(audioBlob);
        
        stream.getTracks().forEach(track => track.stop());
        streamRef.current = null;
      };

      mediaRecorder.start();
      setIsRecording(true);
    } catch (error) {
      console.error('Failed to start recording:', error);
      onError?.('Failed to access microphone. Please check permissions.');
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
    }
  };

  const processAudio = async (audioBlob) => {
    setIsProcessing(true);

    try {
      const result = await api.transcribeAudio(audioBlob);
      
      if (result.text && result.text.trim()) {
        onTranscription?.(result.text, result.confidence);
      } else {
        onError?.('No speech detected. Please try again.');
      }
    } catch (error) {
      console.error('Transcription failed:', error);
      onError?.(error.message || 'Failed to transcribe audio');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleToggleRecording = () => {
    if (isRecording) {
      stopRecording();
    } else {
      startRecording();
    }
  };

  const getButtonColor = () => {
    if (isProcessing) return 'default';
    if (isRecording) return 'error';
    return 'primary';
  };

  const getTooltipText = () => {
    if (isProcessing) return 'Processing audio...';
    if (isRecording) return 'Stop recording (Ctrl+Space)';
    return 'Start voice input (Ctrl+Space)';
  };

  return (
    <Box sx={{ position: 'relative', display: 'inline-flex' }}>
      <Tooltip title={getTooltipText()} arrow>
        <span>
          <IconButton
            onClick={handleToggleRecording}
            disabled={!enabled || isProcessing}
            color={getButtonColor()}
            size="large"
            sx={{
              width: 64,
              height: 64,
              transition: 'all 0.3s ease',
              transform: isRecording ? 'scale(1.1)' : 'scale(1)',
              boxShadow: isRecording
                ? `0 0 ${20 + audioLevel * 30}px rgba(244, 67, 54, ${0.5 + audioLevel * 0.5})`
                : 'none',
            }}
          >
            {isProcessing ? (
              <CircularProgress size={32} />
            ) : isRecording ? (
              <GraphicEqIcon sx={{ fontSize: 32 }} />
            ) : enabled ? (
              <MicIcon sx={{ fontSize: 32 }} />
            ) : (
              <MicOffIcon sx={{ fontSize: 32 }} />
            )}
          </IconButton>
        </span>
      </Tooltip>

      <Fade in={isRecording}>
        <Box
          sx={{
            position: 'absolute',
            bottom: -24,
            left: '50%',
            transform: 'translateX(-50%)',
            whiteSpace: 'nowrap',
          }}
        >
          <Typography variant="caption" color="error">
            Recording...
          </Typography>
        </Box>
      </Fade>

      {isRecording && (
        <Box
          sx={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: 64 + audioLevel * 40,
            height: 64 + audioLevel * 40,
            borderRadius: '50%',
            border: '2px solid',
            borderColor: 'error.main',
            opacity: 0.3,
            transition: 'all 0.1s ease',
            pointerEvents: 'none',
          }}
        />
      )}
    </Box>
  );
}

export default VoiceControl;
