import React, { useState, useEffect } from 'react';
import { Box, Typography, Tooltip, IconButton } from '@mui/material';
import FiberManualRecordIcon from '@mui/icons-material/FiberManualRecord';
import './CompactTaskBar.css';

const CompactTaskBar = ({ tasks = [] }) => {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [systemStatus, setSystemStatus] = useState({
    cpu: 0,
    memory: 0,
    network: 'ONLINE',
  });

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
      updateSystemStatus();
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const updateSystemStatus = () => {
    setSystemStatus({
      cpu: (Math.random() * 100).toFixed(0),
      memory: (Math.random() * 100).toFixed(0),
      network: 'ONLINE',
    });
  };

  const formatTime = (date) => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  };

  const getStatusColor = (value) => {
    if (value < 50) return '#00ff00';
    if (value < 80) return '#ffff00';
    return '#ff0000';
  };

  return (
    <Box className="compact-taskbar">
      <Box className="taskbar-section">
        <Typography variant="caption" className="taskbar-label">
          AETHER
        </Typography>
      </Box>

      <Box className="taskbar-section tasks">
        {tasks.slice(0, 5).map((task, index) => (
          <Tooltip key={index} title={task.name || `Task ${index + 1}`} arrow>
            <Box className="task-indicator">
              <FiberManualRecordIcon 
                sx={{ 
                  fontSize: 8, 
                  color: task.status === 'running' ? '#00ff00' : '#00ffff',
                  animation: task.status === 'running' ? 'task-blink 1s infinite' : 'none'
                }} 
              />
            </Box>
          </Tooltip>
        ))}
      </Box>

      <Box className="taskbar-section stats">
        <Tooltip title={`CPU Usage: ${systemStatus.cpu}%`} arrow>
          <Box className="stat-item">
            <Typography variant="caption" sx={{ color: getStatusColor(systemStatus.cpu) }}>
              CPU {systemStatus.cpu}%
            </Typography>
          </Box>
        </Tooltip>

        <Tooltip title={`Memory Usage: ${systemStatus.memory}%`} arrow>
          <Box className="stat-item">
            <Typography variant="caption" sx={{ color: getStatusColor(systemStatus.memory) }}>
              MEM {systemStatus.memory}%
            </Typography>
          </Box>
        </Tooltip>

        <Box className="stat-item">
          <FiberManualRecordIcon 
            sx={{ 
              fontSize: 8, 
              color: '#00ff00',
              mr: 0.5
            }} 
          />
          <Typography variant="caption" sx={{ color: '#00ff00' }}>
            {systemStatus.network}
          </Typography>
        </Box>
      </Box>

      <Box className="taskbar-section time">
        <Typography variant="caption" className="time-display">
          {formatTime(currentTime)}
        </Typography>
      </Box>
    </Box>
  );
};

export default CompactTaskBar;
