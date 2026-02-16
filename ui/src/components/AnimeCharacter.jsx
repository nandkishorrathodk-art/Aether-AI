import React, { useState, useEffect } from 'react';
import { Box, IconButton, Tooltip, Menu, MenuItem } from '@mui/material';
import PersonIcon from '@mui/icons-material/Person';
import FavoriteIcon from '@mui/icons-material/Favorite';
import ChatBubbleIcon from '@mui/icons-material/ChatBubble';
import './AnimeCharacter.css';

const AnimeCharacter = ({ isListening, isSpeaking, mood = 'neutral' }) => {
  const [position, setPosition] = useState({ x: window.innerWidth - 250, y: window.innerHeight - 350 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);
  const [showHeart, setShowHeart] = useState(false);
  const [blinkState, setBlinkState] = useState(false);
  const [anchorEl, setAnchorEl] = useState(null);
  const [currentPose, setCurrentPose] = useState('idle');
  const [personality, setPersonality] = useState('friendly');

  useEffect(() => {
    const blinkInterval = setInterval(() => {
      setBlinkState(true);
      setTimeout(() => setBlinkState(false), 150);
    }, 3000 + Math.random() * 2000);

    return () => clearInterval(blinkInterval);
  }, []);

  useEffect(() => {
    if (isListening) {
      setCurrentPose('listening');
    } else if (isSpeaking) {
      setCurrentPose('speaking');
    } else {
      setCurrentPose('idle');
    }
  }, [isListening, isSpeaking]);

  const handleMouseDown = (e) => {
    setIsDragging(true);
    setDragOffset({
      x: e.clientX - position.x,
      y: e.clientY - position.y,
    });
  };

  const handleMouseMove = (e) => {
    if (isDragging) {
      setPosition({
        x: e.clientX - dragOffset.x,
        y: e.clientY - dragOffset.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  useEffect(() => {
    if (isDragging) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
    } else {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging]);

  const handleClick = () => {
    setShowHeart(true);
    setTimeout(() => setShowHeart(false), 1000);
  };

  const handleRightClick = (e) => {
    e.preventDefault();
    setAnchorEl(e.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handlePersonalityChange = (newPersonality) => {
    setPersonality(newPersonality);
    handleMenuClose();
  };

  const getCharacterState = () => {
    if (isListening) return 'listening';
    if (isSpeaking) return 'speaking';
    if (isHovered) return 'excited';
    return 'idle';
  };

  const getEyeState = () => {
    if (blinkState) return 'closed';
    if (isListening) return 'focused';
    if (isSpeaking) return 'happy';
    return 'normal';
  };

  const getMouthState = () => {
    if (isSpeaking) return 'talking';
    if (isHovered) return 'smile';
    return 'neutral';
  };

  return (
    <>
      <Box
        className={`anime-character ${currentPose} ${personality}`}
        style={{
          left: position.x,
          top: position.y,
        }}
        onMouseDown={handleMouseDown}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        onClick={handleClick}
        onContextMenu={handleRightClick}
      >
        <Box className="character-body">
          <Box className="character-head">
            <Box className={`character-eyes ${getEyeState()}`}>
              <Box className="eye left">
                <Box className="pupil" />
                {isListening && <Box className="sound-wave" />}
              </Box>
              <Box className="eye right">
                <Box className="pupil" />
                {isListening && <Box className="sound-wave" />}
              </Box>
            </Box>

            <Box className={`character-mouth ${getMouthState()}`}>
              {isSpeaking && (
                <Box className="mouth-animation">
                  <Box className="speech-indicator" />
                </Box>
              )}
            </Box>

            <Box className="character-hair">
              <Box className="hair-strand left" />
              <Box className="hair-strand right" />
              <Box className="hair-bangs" />
            </Box>

            <Box className="character-accessories">
              <Box className="accessory headphones" />
              <Box className="accessory ribbon" />
            </Box>
          </Box>

          <Box className="character-torso">
            <Box className="outfit" />
            <Box className="arms">
              <Box className={`arm left ${currentPose}`} />
              <Box className={`arm right ${currentPose}`} />
            </Box>
          </Box>
        </Box>

        {showHeart && (
          <Box className="floating-heart">
            <FavoriteIcon sx={{ color: '#ff69b4', fontSize: 30 }} />
          </Box>
        )}

        {isListening && (
          <Box className="status-indicator listening">
            <ChatBubbleIcon sx={{ fontSize: 16 }} />
            <span>Listening...</span>
          </Box>
        )}

        {isSpeaking && (
          <Box className="status-indicator speaking">
            <ChatBubbleIcon sx={{ fontSize: 16 }} />
            <span>Speaking...</span>
          </Box>
        )}

        <Tooltip title={`Personality: ${personality}`} arrow>
          <Box className="personality-badge">
            <PersonIcon sx={{ fontSize: 16 }} />
          </Box>
        </Tooltip>
      </Box>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        PaperProps={{
          sx: {
            backgroundColor: 'rgba(0, 20, 20, 0.95)',
            backdropFilter: 'blur(10px)',
            border: '1px solid rgba(0, 255, 255, 0.3)',
          },
        }}
      >
        <MenuItem onClick={() => handlePersonalityChange('friendly')}>
          😊 Friendly
        </MenuItem>
        <MenuItem onClick={() => handlePersonalityChange('playful')}>
          😜 Playful
        </MenuItem>
        <MenuItem onClick={() => handlePersonalityChange('professional')}>
          💼 Professional
        </MenuItem>
        <MenuItem onClick={() => handlePersonalityChange('kawaii')}>
          🎀 Kawaii
        </MenuItem>
        <MenuItem onClick={() => handlePersonalityChange('tsundere')}>
          😤 Tsundere
        </MenuItem>
      </Menu>
    </>
  );
};

export default AnimeCharacter;
