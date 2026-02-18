/**
 * Theme Definitions for Aether AI
 * 
 * Includes 5 themes: Dark, Light, Neon, Hacker, Minimal
 */

export const themes = {
  dark: {
    id: 'dark',
    name: 'Dark Cyber',
    palette: {
      mode: 'dark',
      primary: {
        main: '#00ffff',
        light: '#66ffff',
        dark: '#00cccc',
      },
      secondary: {
        main: '#00ccff',
        light: '#66ddff',
        dark: '#0099cc',
      },
      background: {
        default: '#000000',
        paper: 'rgba(0, 50, 50, 0.3)',
      },
      text: {
        primary: '#00ffff',
        secondary: '#00cccc',
      },
    },
    typography: {
      fontFamily: '"Courier New", monospace',
    },
    custom: {
      glowColor: '#00ffff',
      accentColor: '#ff00ff',
      bubbleGradient: 'linear-gradient(135deg, #00ffff 0%, #0099ff 100%)',
      borderColor: 'rgba(0, 255, 255, 0.3)',
    },
  },

  light: {
    id: 'light',
    name: 'Light Modern',
    palette: {
      mode: 'light',
      primary: {
        main: '#1976d2',
        light: '#42a5f5',
        dark: '#1565c0',
      },
      secondary: {
        main: '#9c27b0',
        light: '#ba68c8',
        dark: '#7b1fa2',
      },
      background: {
        default: '#f5f5f5',
        paper: '#ffffff',
      },
      text: {
        primary: '#212121',
        secondary: '#757575',
      },
    },
    typography: {
      fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    },
    custom: {
      glowColor: '#1976d2',
      accentColor: '#9c27b0',
      bubbleGradient: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      borderColor: 'rgba(0, 0, 0, 0.12)',
    },
  },

  neon: {
    id: 'neon',
    name: 'Neon City',
    palette: {
      mode: 'dark',
      primary: {
        main: '#ff00ff',
        light: '#ff66ff',
        dark: '#cc00cc',
      },
      secondary: {
        main: '#00ff00',
        light: '#66ff66',
        dark: '#00cc00',
      },
      background: {
        default: '#0a0a0a',
        paper: 'rgba(25, 0, 40, 0.8)',
      },
      text: {
        primary: '#ff00ff',
        secondary: '#00ff00',
      },
    },
    typography: {
      fontFamily: '"Orbitron", "Courier New", monospace',
    },
    custom: {
      glowColor: '#ff00ff',
      accentColor: '#00ff00',
      bubbleGradient: 'linear-gradient(135deg, #ff00ff 0%, #00ff00 100%)',
      borderColor: 'rgba(255, 0, 255, 0.5)',
    },
  },

  hacker: {
    id: 'hacker',
    name: 'Hacker Terminal',
    palette: {
      mode: 'dark',
      primary: {
        main: '#00ff00',
        light: '#66ff66',
        dark: '#00cc00',
      },
      secondary: {
        main: '#00ff00',
        light: '#66ff66',
        dark: '#00cc00',
      },
      background: {
        default: '#000000',
        paper: 'rgba(0, 20, 0, 0.9)',
      },
      text: {
        primary: '#00ff00',
        secondary: '#00cc00',
      },
    },
    typography: {
      fontFamily: '"Fira Code", "Courier New", monospace',
    },
    custom: {
      glowColor: '#00ff00',
      accentColor: '#00ff00',
      bubbleGradient: 'linear-gradient(135deg, #001100 0%, #003300 100%)',
      borderColor: 'rgba(0, 255, 0, 0.3)',
      scanlineEffect: true,
    },
  },

  minimal: {
    id: 'minimal',
    name: 'Minimal Clean',
    palette: {
      mode: 'light',
      primary: {
        main: '#000000',
        light: '#424242',
        dark: '#000000',
      },
      secondary: {
        main: '#757575',
        light: '#9e9e9e',
        dark: '#616161',
      },
      background: {
        default: '#ffffff',
        paper: '#fafafa',
      },
      text: {
        primary: '#000000',
        secondary: '#757575',
      },
    },
    typography: {
      fontFamily: '"Inter", "Helvetica Neue", sans-serif',
    },
    custom: {
      glowColor: '#000000',
      accentColor: '#000000',
      bubbleGradient: 'linear-gradient(135deg, #f5f5f5 0%, #e0e0e0 100%)',
      borderColor: 'rgba(0, 0, 0, 0.08)',
    },
  },
};

export const getTheme = (themeId) => {
  return themes[themeId] || themes.dark;
};

export const getThemeIds = () => {
  return Object.keys(themes);
};

export const getThemeNames = () => {
  return Object.values(themes).map(t => ({ id: t.id, name: t.name }));
};
