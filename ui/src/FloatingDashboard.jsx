import React, { useState } from 'react';
import { Box, IconButton, Tooltip, Fade, Zoom } from '@mui/material';
import {
  DragIndicator,
  Minimize,
  Close,
  Settings,
  Mic,
  Chat,
  Memory,
  Security,
  Code
} from '@mui/icons-material';
import './FloatingDashboard.css';

const FloatingDashboard = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState('chat');

  const handleMinimize = () => {
    window.electron?.send('minimize-window');
  };

  const handleClose = () => {
    window.electron?.send('close-window');
  };

  const tabs = [
    { id: 'chat', icon: <Chat />, label: 'Chat', color: '#6366f1' },
    { id: 'voice', icon: <Mic />, label: 'Voice', color: '#8b5cf6' },
    { id: 'memory', icon: <Memory />, label: 'Memory', color: '#ec4899' },
    { id: 'security', icon: <Security />, label: 'Security', color: '#f59e0b' },
    { id: 'code', icon: <Code />, label: 'Code', color: '#10b981' },
  ];

  return (
    <Fade in timeout={500}>
      <Box className="floating-dashboard">
        {/* Custom Drag Bar */}
        <Box className="drag-bar" style={{ WebkitAppRegion: 'drag' }}>
          <Box className="drag-bar-left">
            <DragIndicator className="drag-icon" />
            <span className="app-title">Aether AI</span>
          </Box>
          <Box className="drag-bar-right" style={{ WebkitAppRegion: 'no-drag' }}>
            <Tooltip title="Minimize">
              <IconButton size="small" onClick={handleMinimize} className="window-btn">
                <Minimize fontSize="small" />
              </IconButton>
            </Tooltip>
            <Tooltip title="Close">
              <IconButton size="small" onClick={handleClose} className="window-btn close-btn">
                <Close fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Animated Side Tab Bar */}
        <Box className="side-tabs">
          {tabs.map((tab, index) => (
            <Zoom in timeout={300 + index * 100} key={tab.id}>
              <Tooltip title={tab.label} placement="right">
                <IconButton
                  className={`tab-button ${activeTab === tab.id ? 'active' : ''}`}
                  onClick={() => setActiveTab(tab.id)}
                  sx={{
                    color: activeTab === tab.id ? tab.color : '#94a3b8',
                    '&:hover': {
                      color: tab.color,
                      backgroundColor: `${tab.color}15`
                    }
                  }}
                >
                  {tab.icon}
                </IconButton>
              </Tooltip>
            </Zoom>
          ))}
        </Box>

        {/* Main Content Area */}
        <Box className="dashboard-content">
          <Fade in timeout={400}>
            <Box className="content-wrapper">
              {children}
            </Box>
          </Fade>
        </Box>

        {/* Floating Action Button */}
        <Box className="fab-container">
          <Tooltip title="Settings">
            <IconButton className="fab-button">
              <Settings />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>
    </Fade>
  );
};

export default FloatingDashboard;
