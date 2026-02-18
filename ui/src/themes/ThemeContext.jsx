/**
 * Theme Context Provider
 * Manages theme state across the application
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { ThemeProvider as MuiThemeProvider, createTheme } from '@mui/material/styles';
import { getTheme } from './themes';

const ThemeContext = createContext();

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return context;
};

export const ThemeProvider = ({ children }) => {
  const [currentThemeId, setCurrentThemeId] = useState(() => {
    // Load theme from localStorage
    return localStorage.getItem('aether-theme') || 'dark';
  });

  const themeConfig = getTheme(currentThemeId);
  const muiTheme = createTheme(themeConfig);

  useEffect(() => {
    // Save theme to localStorage
    localStorage.setItem('aether-theme', currentThemeId);
    
    // Apply custom CSS variables for non-MUI styles
    const root = document.documentElement;
    root.style.setProperty('--primary-color', themeConfig.palette.primary.main);
    root.style.setProperty('--secondary-color', themeConfig.palette.secondary.main);
    root.style.setProperty('--background-color', themeConfig.palette.background.default);
    root.style.setProperty('--paper-color', themeConfig.palette.background.paper);
    root.style.setProperty('--text-primary', themeConfig.palette.text.primary);
    root.style.setProperty('--text-secondary', themeConfig.palette.text.secondary);
    root.style.setProperty('--glow-color', themeConfig.custom.glowColor);
    root.style.setProperty('--accent-color', themeConfig.custom.accentColor);
    root.style.setProperty('--bubble-gradient', themeConfig.custom.bubbleGradient);
    root.style.setProperty('--border-color', themeConfig.custom.borderColor);
    
    // Apply theme class to body
    document.body.className = `theme-${currentThemeId}`;
  }, [currentThemeId, themeConfig]);

  const changeTheme = (themeId) => {
    setCurrentThemeId(themeId);
  };

  const value = {
    currentThemeId,
    themeConfig,
    changeTheme,
  };

  return (
    <ThemeContext.Provider value={value}>
      <MuiThemeProvider theme={muiTheme}>
        {children}
      </MuiThemeProvider>
    </ThemeContext.Provider>
  );
};
