import React, { useState, useEffect, useRef } from 'react';
import { Box, Typography, IconButton } from '@mui/material';
import MicIcon from '@mui/icons-material/Mic';
import MicOffIcon from '@mui/icons-material/MicOff';
import './JarvisDashboard.css';

const JarvisDashboard = ({ onVoiceCommand }) => {
  const [isListening, setIsListening] = useState(false);
  const [audioLevel, setAudioLevel] = useState(0);
  const [cpuUsage, setCpuUsage] = useState(0);
  const [memoryUsage, setMemoryUsage] = useState(0);
  const [taskCount, setTaskCount] = useState(0);
  const canvasRef = useRef(null);
  const animationRef = useRef(null);
  const audioContextRef = useRef(null);
  const analyserRef = useRef(null);

  useEffect(() => {
    drawJarvisCore();
    updateSystemStats();
    const interval = setInterval(updateSystemStats, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (isListening) {
      startAudioVisualization();
    } else {
      stopAudioVisualization();
    }
  }, [isListening]);

  const drawJarvisCore = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;

    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const time = Date.now() / 1000;

      for (let i = 0; i < 4; i++) {
        const radius = 60 + i * 30 + Math.sin(time + i) * 5;
        const alpha = 0.3 - i * 0.05;

        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 255, 255, ${alpha})`;
        ctx.lineWidth = 2;
        ctx.stroke();

        for (let j = 0; j < 12; j++) {
          const angle = (j * Math.PI * 2) / 12 + time * 0.5;
          const tickLength = 10;
          const x1 = centerX + Math.cos(angle) * (radius - tickLength);
          const y1 = centerY + Math.sin(angle) * (radius - tickLength);
          const x2 = centerX + Math.cos(angle) * radius;
          const y2 = centerY + Math.sin(angle) * radius;

          ctx.beginPath();
          ctx.moveTo(x1, y1);
          ctx.lineTo(x2, y2);
          ctx.strokeStyle = `rgba(0, 255, 255, ${alpha})`;
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      }

      const pulseRadius = 30 + Math.sin(time * 2) * 5 + audioLevel * 20;
      const gradient = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, pulseRadius);
      gradient.addColorStop(0, 'rgba(0, 255, 255, 0.8)');
      gradient.addColorStop(0.5, 'rgba(0, 200, 255, 0.4)');
      gradient.addColorStop(1, 'rgba(0, 150, 255, 0)');

      ctx.beginPath();
      ctx.arc(centerX, centerY, pulseRadius, 0, Math.PI * 2);
      ctx.fillStyle = gradient;
      ctx.fill();

      drawTechLines(ctx, centerX, centerY, time);

      animationRef.current = requestAnimationFrame(animate);
    };

    animate();
  };

  const drawTechLines = (ctx, centerX, centerY, time) => {
    const lines = [
      { angle: 0, length: 200 },
      { angle: Math.PI / 4, length: 150 },
      { angle: Math.PI / 2, length: 180 },
      { angle: (3 * Math.PI) / 4, length: 160 },
      { angle: Math.PI, length: 200 },
      { angle: (5 * Math.PI) / 4, length: 170 },
      { angle: (3 * Math.PI) / 2, length: 190 },
      { angle: (7 * Math.PI) / 4, length: 150 }
    ];

    lines.forEach((line, i) => {
      const startRadius = 150;
      const endRadius = startRadius + line.length;
      const angle = line.angle + Math.sin(time + i) * 0.1;

      const x1 = centerX + Math.cos(angle) * startRadius;
      const y1 = centerY + Math.sin(angle) * startRadius;
      const x2 = centerX + Math.cos(angle) * endRadius;
      const y2 = centerY + Math.sin(angle) * endRadius;

      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.strokeStyle = `rgba(0, 200, 255, ${0.3 + Math.sin(time * 2 + i) * 0.2})`;
      ctx.lineWidth = 1;
      ctx.stroke();

      const nodeX = x2;
      const nodeY = y2;
      ctx.beginPath();
      ctx.arc(nodeX, nodeY, 3, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 255, 255, 0.8)';
      ctx.fill();

      const boxWidth = 80;
      const boxHeight = 40;
      ctx.strokeStyle = 'rgba(0, 255, 255, 0.3)';
      ctx.lineWidth = 1;
      ctx.strokeRect(nodeX - boxWidth / 2, nodeY - boxHeight / 2, boxWidth, boxHeight);
    });
  };

  const startAudioVisualization = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const audioContext = new (window.AudioContext || window.webkitAudioContext)();
      const analyser = audioContext.createAnalyser();
      const microphone = audioContext.createMediaStreamSource(stream);

      analyser.fftSize = 256;
      microphone.connect(analyser);

      audioContextRef.current = audioContext;
      analyserRef.current = analyser;

      const dataArray = new Uint8Array(analyser.frequencyBinCount);

      const updateAudioLevel = () => {
        if (!analyserRef.current) return;

        analyser.getByteFrequencyData(dataArray);
        const average = dataArray.reduce((a, b) => a + b) / dataArray.length;
        setAudioLevel(average / 255);

        requestAnimationFrame(updateAudioLevel);
      };

      updateAudioLevel();
    } catch (error) {
      console.error('Audio visualization error:', error);
    }
  };

  const stopAudioVisualization = () => {
    if (audioContextRef.current) {
      audioContextRef.current.close();
      audioContextRef.current = null;
    }
    analyserRef.current = null;
    setAudioLevel(0);
  };

  const updateSystemStats = () => {
    setCpuUsage(Math.random() * 100);
    setMemoryUsage(Math.random() * 100);
    setTaskCount(Math.floor(Math.random() * 20));
  };

  const toggleVoiceListening = () => {
    setIsListening(!isListening);
    if (!isListening && onVoiceCommand) {
      onVoiceCommand('start');
    }
  };

  return (
    <Box className="jarvis-dashboard">
      <canvas
        ref={canvasRef}
        width={800}
        height={600}
        className="jarvis-canvas"
      />

      <Box className="jarvis-header">
        <Typography variant="h5" className="jarvis-title">
          AETHER AI - OPERATIONAL
        </Typography>
        <Typography variant="caption" className="jarvis-subtitle">
          HYPER-ADVANCED SYSTEM v0.3.0
        </Typography>
      </Box>

      <Box className="voice-control">
        <IconButton
          onClick={toggleVoiceListening}
          className={`voice-button ${isListening ? 'active' : ''}`}
          size="large"
        >
          {isListening ? <MicIcon fontSize="large" /> : <MicOffIcon fontSize="large" />}
        </IconButton>
        <Typography variant="caption" className="voice-status">
          {isListening ? 'LISTENING...' : 'VOICE INACTIVE'}
        </Typography>
      </Box>

      <Box className="stats-panel top-left">
        <Typography variant="caption" className="stat-label">CPU USAGE</Typography>
        <Typography variant="h6" className="stat-value">{cpuUsage.toFixed(1)}%</Typography>
        <Box className="stat-bar">
          <Box className="stat-fill" style={{ width: `${cpuUsage}%` }} />
        </Box>
      </Box>

      <Box className="stats-panel top-right">
        <Typography variant="caption" className="stat-label">MEMORY</Typography>
        <Typography variant="h6" className="stat-value">{memoryUsage.toFixed(1)}%</Typography>
        <Box className="stat-bar">
          <Box className="stat-fill" style={{ width: `${memoryUsage}%` }} />
        </Box>
      </Box>

      <Box className="stats-panel bottom-left">
        <Typography variant="caption" className="stat-label">ACTIVE TASKS</Typography>
        <Typography variant="h6" className="stat-value">{taskCount}</Typography>
      </Box>

      <Box className="stats-panel bottom-right">
        <Typography variant="caption" className="stat-label">AI STATUS</Typography>
        <Typography variant="h6" className="stat-value status-online">ONLINE</Typography>
      </Box>

      {isListening && (
        <Box className="audio-indicator">
          <Box 
            className="audio-pulse" 
            style={{ 
              transform: `scale(${1 + audioLevel})`,
              opacity: 0.5 + audioLevel * 0.5
            }} 
          />
        </Box>
      )}
    </Box>
  );
};

export default JarvisDashboard;
