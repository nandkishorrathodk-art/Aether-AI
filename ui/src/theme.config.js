export const themes = {
  cyberpunk: {
    name: 'Cyberpunk (Default)',
    colors: {
      primary: '#00ffff',
      secondary: '#ff00ff',
      background: 'rgba(0, 20, 40, 0.9)',
      text: '#ffffff',
      muted: '#666666',
      idle: '#00ffff'
    },
    effects: {
      glow: true,
      glitch: true,
      neonBorder: true
    }
  },
  matrix: {
    name: 'Matrix',
    colors: {
      primary: '#00ff00',
      secondary: '#00cc00',
      background: 'rgba(0, 0, 0, 0.95)',
      text: '#00ff00',
      muted: '#004400',
      idle: '#00ff00'
    },
    effects: {
      glow: true,
      glitch: false,
      neonBorder: true
    }
  },
  ironman: {
    name: 'Iron Man',
    colors: {
      primary: '#ff4444',
      secondary: '#ffaa00',
      background: 'rgba(40, 0, 0, 0.9)',
      text: '#ffaa00',
      muted: '#884422',
      idle: '#ff4444'
    },
    effects: {
      glow: true,
      glitch: false,
      neonBorder: true
    }
  },
  minimal: {
    name: 'Minimal Light',
    colors: {
      primary: '#2196f3',
      secondary: '#00bcd4',
      background: 'rgba(255, 255, 255, 0.95)',
      text: '#212121',
      muted: '#9e9e9e',
      idle: '#2196f3'
    },
    effects: {
      glow: false,
      glitch: false,
      neonBorder: false
    }
  },
  dark: {
    name: 'Dark Mode',
    colors: {
      primary: '#bb86fc',
      secondary: '#03dac6',
      background: 'rgba(18, 18, 18, 0.95)',
      text: '#ffffff',
      muted: '#666666',
      idle: '#bb86fc'
    },
    effects: {
      glow: true,
      glitch: false,
      neonBorder: false
    }
  }
};

export const defaultTheme = 'cyberpunk';

export const getTheme = (themeName = defaultTheme) => {
  return themes[themeName] || themes[defaultTheme];
};
