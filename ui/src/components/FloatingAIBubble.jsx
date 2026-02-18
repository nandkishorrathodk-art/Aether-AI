/**
 * Floating AI Bubble Component
 * ChatGPT-style floating bubble that can be dragged anywhere on screen
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Box,
  IconButton,
  Tooltip,
  Fade,
  Paper,
  Typography,
  Zoom,
  Badge,
} from '@mui/material';
import {
  SmartToy,
  Close,
  Minimize,
  FullscreenExit,
  DragIndicator,
  Chat,
  Mic,
  Settings,
  Lightbulb,
} from '@mui/icons-material';
import './FloatingAIBubble.css';

const FloatingAIBubble = ({ onOpenChat, onOpenVoice, onOpenSettings, notifications = 0 }) => {
  const [expanded, setExpanded] = useState(false);
  const [position, setPosition] = useState({
    x: window.innerWidth - 100,
    y: window.innerHeight - 100,
  });
  const [dragging, setDragging] = useState(false);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [pulse, setPulse] = useState(false);
  const bubbleRef = useRef(null);

  // Pulse animation on notifications
  useEffect(() => {
    if (notifications > 0) {
      setPulse(true);
      setTimeout(() => setPulse(false), 1000);
    }
  }, [notifications]);

  const handleMouseDown = (e) => {
    if (expanded) return; // Don't drag when expanded
    
    setDragging(true);
    const rect = bubbleRef.current.getBoundingClientRect();
    setOffset({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const handleMouseMove = (e) => {
    if (!dragging) return;

    const newX = e.clientX - offset.x;
    const newY = e.clientY - offset.y;

    // Keep bubble within bounds
    const maxX = window.innerWidth - 80;
    const maxY = window.innerHeight - 80;

    setPosition({
      x: Math.max(0, Math.min(newX, maxX)),
      y: Math.max(0, Math.min(newY, maxY)),
    });
  };

  const handleMouseUp = () => {
    setDragging(false);
  };

  useEffect(() => {
    if (dragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
    } else {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    }

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [dragging, offset]);

  const quickActions = [
    { icon: <Chat />, label: 'Chat', color: '#00ffff', action: onOpenChat },
    { icon: <Mic />, label: 'Voice', color: '#9c27b0', action: onOpenVoice },
    { icon: <Lightbulb />, label: 'Suggestions', color: '#ffc107', action: () => {} },
    { icon: <Settings />, label: 'Settings', color: '#4caf50', action: onOpenSettings },
  ];

  return (
    <Box
      ref={bubbleRef}
      className={`floating-ai-bubble ${expanded ? 'expanded' : ''} ${pulse ? 'pulse' : ''}`}
      sx={{
        position: 'fixed',
        left: `${position.x}px`,
        top: `${position.y}px`,
        zIndex: 9999,
        cursor: dragging ? 'grabbing' : expanded ? 'default' : 'grab',
        transition: dragging ? 'none' : 'left 0.2s, top 0.2s',
      }}
    >
      {!expanded ? (
        // Collapsed Bubble
        <Zoom in timeout={300}>
          <Paper
            className="bubble-collapsed"
            elevation={8}
            onMouseDown={handleMouseDown}
            onClick={() => setExpanded(true)}
            sx={{
              width: 70,
              height: 70,
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'var(--bubble-gradient)',
              border: '2px solid var(--border-color)',
              boxShadow: '0 0 20px var(--glow-color)',
              cursor: 'pointer',
              '&:hover': {
                transform: 'scale(1.1)',
                boxShadow: '0 0 30px var(--glow-color)',
              },
              transition: 'all 0.3s',
            }}
          >
            <Badge
              badgeContent={notifications}
              color="error"
              overlap="circular"
            >
              <SmartToy sx={{ fontSize: 36, color: '#fff' }} />
            </Badge>
          </Paper>
        </Zoom>
      ) : (
        // Expanded Panel
        <Fade in timeout={300}>
          <Paper
            className="bubble-expanded"
            elevation={16}
            sx={{
              width: 300,
              minHeight: 200,
              borderRadius: 4,
              background: 'var(--paper-color)',
              backdropFilter: 'blur(20px)',
              border: '1px solid var(--border-color)',
              boxShadow: '0 10px 40px rgba(0, 0, 0, 0.5)',
              overflow: 'hidden',
            }}
          >
            {/* Header */}
            <Box
              className="bubble-header"
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                p: 1.5,
                background: 'var(--bubble-gradient)',
                borderBottom: '1px solid var(--border-color)',
                cursor: 'grab',
              }}
              onMouseDown={handleMouseDown}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <DragIndicator sx={{ color: '#fff', fontSize: 20 }} />
                <Typography variant="h6" sx={{ color: '#fff', fontWeight: 600 }}>
                  Aether AI
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', gap: 0.5 }}>
                <Tooltip title="Minimize">
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      setExpanded(false);
                    }}
                    sx={{ color: '#fff' }}
                  >
                    <Minimize fontSize="small" />
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>

            {/* Content */}
            <Box sx={{ p: 2 }}>
              <Typography
                variant="body2"
                sx={{ mb: 2, color: 'var(--text-secondary)' }}
              >
                Hi Boss! 👋 Aaj kya karein?
              </Typography>

              {/* Quick Actions */}
              <Box
                sx={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, 1fr)',
                  gap: 1.5,
                }}
              >
                {quickActions.map((action, index) => (
                  <Zoom in timeout={300 + index * 100} key={action.label}>
                    <Paper
                      className="quick-action-btn"
                      onClick={action.action}
                      elevation={2}
                      sx={{
                        p: 2,
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        gap: 1,
                        cursor: 'pointer',
                        background: 'rgba(255, 255, 255, 0.03)',
                        border: '1px solid var(--border-color)',
                        borderRadius: 2,
                        transition: 'all 0.3s',
                        '&:hover': {
                          background: 'rgba(255, 255, 255, 0.08)',
                          borderColor: action.color,
                          transform: 'translateY(-2px)',
                          boxShadow: `0 4px 12px ${action.color}40`,
                        },
                      }}
                    >
                      <Box
                        sx={{
                          color: action.color,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        {action.icon}
                      </Box>
                      <Typography
                        variant="caption"
                        sx={{ color: 'var(--text-primary)', fontWeight: 500 }}
                      >
                        {action.label}
                      </Typography>
                    </Paper>
                  </Zoom>
                ))}
              </Box>

              {/* Status */}
              <Box
                sx={{
                  mt: 2,
                  p: 1.5,
                  background: 'rgba(0, 255, 0, 0.1)',
                  border: '1px solid rgba(0, 255, 0, 0.3)',
                  borderRadius: 2,
                }}
              >
                <Typography
                  variant="caption"
                  sx={{ color: '#00ff00', fontWeight: 500 }}
                >
                  ✅ All systems operational
                </Typography>
              </Box>
            </Box>
          </Paper>
        </Fade>
      )}
    </Box>
  );
};

export default FloatingAIBubble;
