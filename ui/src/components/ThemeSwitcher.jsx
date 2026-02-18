/**
 * Theme Switcher Component
 * Allows users to switch between different themes
 */

import React, { useState } from 'react';
import {
  Box,
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Typography,
  Paper,
  Tooltip,
  Zoom,
} from '@mui/material';
import {
  Palette,
  DarkMode,
  LightMode,
  Flare,
  Code,
  RemoveRedEye,
  Check,
} from '@mui/icons-material';
import { useTheme } from '../themes/ThemeContext';
import { getThemeNames } from '../themes/themes';

const ThemeSwitcher = () => {
  const { currentThemeId, changeTheme } = useTheme();
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  const handleClick = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleThemeChange = (themeId) => {
    changeTheme(themeId);
    handleClose();
  };

  const themeIcons = {
    dark: <DarkMode />,
    light: <LightMode />,
    neon: <Flare />,
    hacker: <Code />,
    minimal: <RemoveRedEye />,
  };

  const themeDescriptions = {
    dark: 'Cyberpunk dark theme with cyan accents',
    light: 'Modern light theme for daytime use',
    neon: 'Vibrant neon city aesthetic',
    hacker: 'Classic green terminal style',
    minimal: 'Clean and simple design',
  };

  const themes = getThemeNames();

  return (
    <>
      <Tooltip title="Change Theme">
        <IconButton
          onClick={handleClick}
          sx={{
            backgroundColor: open
              ? 'var(--primary-color)20'
              : 'rgba(255, 255, 255, 0.05)',
            border: '1px solid var(--border-color)',
            color: 'var(--primary-color)',
            '&:hover': {
              backgroundColor: 'var(--primary-color)30',
              boxShadow: '0 0 10px var(--glow-color)',
            },
            transition: 'all 0.3s',
          }}
        >
          <Palette />
        </IconButton>
      </Tooltip>

      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{
          elevation: 8,
          sx: {
            minWidth: 280,
            background: 'var(--paper-color)',
            backdropFilter: 'blur(20px)',
            border: '1px solid var(--border-color)',
            mt: 1.5,
          },
        }}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        <Box sx={{ px: 2, py: 1.5 }}>
          <Typography
            variant="subtitle2"
            sx={{ color: 'var(--text-primary)', fontWeight: 600 }}
          >
            Choose Theme
          </Typography>
          <Typography
            variant="caption"
            sx={{ color: 'var(--text-secondary)' }}
          >
            Customize your Aether experience
          </Typography>
        </Box>

        <Divider sx={{ borderColor: 'var(--border-color)' }} />

        {themes.map((theme, index) => (
          <Zoom in timeout={200 + index * 50} key={theme.id}>
            <MenuItem
              onClick={() => handleThemeChange(theme.id)}
              selected={currentThemeId === theme.id}
              sx={{
                mx: 1,
                my: 0.5,
                borderRadius: 1,
                '&.Mui-selected': {
                  backgroundColor: 'var(--primary-color)20',
                  '&:hover': {
                    backgroundColor: 'var(--primary-color)30',
                  },
                },
                '&:hover': {
                  backgroundColor: 'rgba(255, 255, 255, 0.05)',
                },
              }}
            >
              <ListItemIcon
                sx={{
                  color:
                    currentThemeId === theme.id
                      ? 'var(--primary-color)'
                      : 'var(--text-secondary)',
                }}
              >
                {themeIcons[theme.id]}
              </ListItemIcon>
              <ListItemText
                primary={theme.name}
                secondary={themeDescriptions[theme.id]}
                primaryTypographyProps={{
                  sx: {
                    color: 'var(--text-primary)',
                    fontWeight: currentThemeId === theme.id ? 600 : 400,
                  },
                }}
                secondaryTypographyProps={{
                  sx: {
                    color: 'var(--text-secondary)',
                    fontSize: '0.75rem',
                  },
                }}
              />
              {currentThemeId === theme.id && (
                <Check
                  sx={{
                    color: 'var(--primary-color)',
                    fontSize: 20,
                    ml: 1,
                  }}
                />
              )}
            </MenuItem>
          </Zoom>
        ))}

        <Divider sx={{ borderColor: 'var(--border-color)', my: 1 }} />

        <Box sx={{ px: 2, py: 1 }}>
          <Typography
            variant="caption"
            sx={{ color: 'var(--text-secondary)', fontStyle: 'italic' }}
          >
            ✨ Theme persists across sessions
          </Typography>
        </Box>
      </Menu>
    </>
  );
};

export default ThemeSwitcher;
