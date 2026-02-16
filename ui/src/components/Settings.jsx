import React, { useState, useEffect } from 'react';
import {
  Box,
  Drawer,
  Typography,
  IconButton,
  Switch,
  FormControlLabel,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Divider,
  Alert,
  Snackbar,
  Tabs,
  Tab,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import SaveIcon from '@mui/icons-material/Save';
import RestoreIcon from '@mui/icons-material/Restore';
import api from '../services/api';

function TabPanel({ children, value, index }) {
  return (
    <Box hidden={value !== index} sx={{ p: 3 }}>
      {value === index && children}
    </Box>
  );
}

function Settings({ open, onClose }) {
  const [activeTab, setActiveTab] = useState(0);
  const [settings, setSettings] = useState(null);
  const [localSettings, setLocalSettings] = useState({
    autoLaunch: false,
    minimizeToTray: true,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [saveStatus, setSaveStatus] = useState({ open: false, message: '', severity: 'success' });

  useEffect(() => {
    if (open) {
      loadSettings();
      loadLocalSettings();
    }
  }, [open]);

  const loadSettings = async () => {
    try {
      const data = await api.getSettings();
      setSettings(data);
    } catch (error) {
      console.error('Failed to load settings:', error);
      setSaveStatus({
        open: true,
        message: 'Failed to load settings',
        severity: 'error',
      });
    }
  };

  const loadLocalSettings = async () => {
    try {
      const autoLaunch = await window.electron?.ipcRenderer.invoke('get-store-value', 'autoLaunch', false);
      const minimizeToTray = await window.electron?.ipcRenderer.invoke('get-store-value', 'minimizeToTray', true);
      
      setLocalSettings({ autoLaunch, minimizeToTray });
    } catch (error) {
      console.error('Failed to load local settings:', error);
    }
  };

  const handleSaveSettings = async () => {
    setIsLoading(true);

    try {
      await api.updateSettings(settings);

      await window.electron?.ipcRenderer.invoke('set-auto-launch', localSettings.autoLaunch);
      await window.electron?.ipcRenderer.invoke('set-store-value', 'minimizeToTray', localSettings.minimizeToTray);

      setSaveStatus({
        open: true,
        message: 'Settings saved successfully',
        severity: 'success',
      });
    } catch (error) {
      console.error('Failed to save settings:', error);
      setSaveStatus({
        open: true,
        message: 'Failed to save settings',
        severity: 'error',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetSettings = async () => {
    if (window.confirm('Are you sure you want to reset all settings to defaults?')) {
      try {
        await api.updateSettings({});
        await loadSettings();
        
        setSaveStatus({
          open: true,
          message: 'Settings reset to defaults',
          severity: 'info',
        });
      } catch (error) {
        console.error('Failed to reset settings:', error);
        setSaveStatus({
          open: true,
          message: 'Failed to reset settings',
          severity: 'error',
        });
      }
    }
  };

  const updateSetting = (category, key, value) => {
    setSettings((prev) => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value,
      },
    }));
  };

  if (!settings) {
    return null;
  }

  return (
    <>
      <Drawer anchor="right" open={open} onClose={onClose} sx={{ zIndex: 1300 }}>
        <Box sx={{ width: 400, height: '100%', display: 'flex', flexDirection: 'column' }}>
          <Box sx={{ p: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography variant="h6">Settings</Typography>
            <IconButton onClick={onClose}>
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider />

          <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)} sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tab label="General" />
            <Tab label="Voice" />
            <Tab label="AI" />
            <Tab label="Memory" />
          </Tabs>

          <Box sx={{ flex: 1, overflowY: 'auto' }}>
            <TabPanel value={activeTab} index={0}>
              <Typography variant="subtitle2" gutterBottom>
                Application
              </Typography>
              
              <FormControlLabel
                control={
                  <Switch
                    checked={localSettings.autoLaunch}
                    onChange={(e) => setLocalSettings({ ...localSettings, autoLaunch: e.target.checked })}
                  />
                }
                label="Launch on startup"
              />
              
              <FormControlLabel
                control={
                  <Switch
                    checked={localSettings.minimizeToTray}
                    onChange={(e) => setLocalSettings({ ...localSettings, minimizeToTray: e.target.checked })}
                  />
                }
                label="Minimize to tray"
              />

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                System
              </Typography>

              <TextField
                fullWidth
                label="Log Level"
                select
                value={settings.system?.log_level || 'INFO'}
                onChange={(e) => updateSetting('system', 'log_level', e.target.value)}
                margin="normal"
                size="small"
              >
                <MenuItem value="DEBUG">Debug</MenuItem>
                <MenuItem value="INFO">Info</MenuItem>
                <MenuItem value="WARNING">Warning</MenuItem>
                <MenuItem value="ERROR">Error</MenuItem>
              </TextField>

              <TextField
                fullWidth
                label="Max Log Size (MB)"
                type="number"
                value={settings.system?.max_log_size_mb || 10}
                onChange={(e) => updateSetting('system', 'max_log_size_mb', parseInt(e.target.value))}
                margin="normal"
                size="small"
              />
            </TabPanel>

            <TabPanel value={activeTab} index={1}>
              <Typography variant="subtitle2" gutterBottom>
                Speech Recognition
              </Typography>

              <FormControlLabel
                control={
                  <Switch
                    checked={settings.voice?.stt_enabled ?? true}
                    onChange={(e) => updateSetting('voice', 'stt_enabled', e.target.checked)}
                  />
                }
                label="Enable voice input"
              />

              <TextField
                fullWidth
                label="STT Model"
                select
                value={settings.voice?.stt_model || 'whisper-1'}
                onChange={(e) => updateSetting('voice', 'stt_model', e.target.value)}
                margin="normal"
                size="small"
              >
                <MenuItem value="whisper-1">OpenAI Whisper</MenuItem>
                <MenuItem value="whisper-tiny">Whisper Tiny (Local)</MenuItem>
                <MenuItem value="whisper-base">Whisper Base (Local)</MenuItem>
                <MenuItem value="whisper-small">Whisper Small (Local)</MenuItem>
              </TextField>

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                Text-to-Speech
              </Typography>

              <FormControlLabel
                control={
                  <Switch
                    checked={settings.voice?.tts_enabled ?? true}
                    onChange={(e) => updateSetting('voice', 'tts_enabled', e.target.checked)}
                  />
                }
                label="Enable voice output"
              />

              <TextField
                fullWidth
                label="Voice"
                select
                value={settings.voice?.tts_voice || 'default'}
                onChange={(e) => updateSetting('voice', 'tts_voice', e.target.value)}
                margin="normal"
                size="small"
              >
                <MenuItem value="default">Default</MenuItem>
                <MenuItem value="alloy">Alloy</MenuItem>
                <MenuItem value="echo">Echo</MenuItem>
                <MenuItem value="fable">Fable</MenuItem>
                <MenuItem value="onyx">Onyx</MenuItem>
                <MenuItem value="nova">Nova</MenuItem>
                <MenuItem value="shimmer">Shimmer</MenuItem>
              </TextField>

              <TextField
                fullWidth
                label="Speech Rate"
                type="number"
                inputProps={{ min: 0.5, max: 2, step: 0.1 }}
                value={settings.voice?.speech_rate || 1.0}
                onChange={(e) => updateSetting('voice', 'speech_rate', parseFloat(e.target.value))}
                margin="normal"
                size="small"
              />
            </TabPanel>

            <TabPanel value={activeTab} index={2}>
              <Typography variant="subtitle2" gutterBottom>
                AI Provider
              </Typography>

              <TextField
                fullWidth
                label="Default Provider"
                select
                value={settings.ai?.default_provider || 'groq'}
                onChange={(e) => updateSetting('ai', 'default_provider', e.target.value)}
                margin="normal"
                size="small"
              >
                <MenuItem value="groq">Groq (Fast & Free)</MenuItem>
                <MenuItem value="openai">OpenAI</MenuItem>
                <MenuItem value="anthropic">Anthropic</MenuItem>
                <MenuItem value="google">Google</MenuItem>
                <MenuItem value="fireworks">Fireworks AI</MenuItem>
                <MenuItem value="openrouter">OpenRouter</MenuItem>
              </TextField>

              <TextField
                fullWidth
                label="Temperature"
                type="number"
                inputProps={{ min: 0, max: 2, step: 0.1 }}
                value={settings.ai?.temperature || 0.7}
                onChange={(e) => updateSetting('ai', 'temperature', parseFloat(e.target.value))}
                margin="normal"
                size="small"
                helperText="Higher = more creative, Lower = more focused"
              />

              <TextField
                fullWidth
                label="Max Tokens"
                type="number"
                value={settings.ai?.max_tokens || 2000}
                onChange={(e) => updateSetting('ai', 'max_tokens', parseInt(e.target.value))}
                margin="normal"
                size="small"
              />

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                Cost Management
              </Typography>

              <FormControlLabel
                control={
                  <Switch
                    checked={settings.ai?.cost_tracking_enabled ?? true}
                    onChange={(e) => updateSetting('ai', 'cost_tracking_enabled', e.target.checked)}
                  />
                }
                label="Enable cost tracking"
              />

              <TextField
                fullWidth
                label="Daily Budget Limit ($)"
                type="number"
                inputProps={{ min: 0, step: 0.01 }}
                value={settings.ai?.daily_budget_limit || 1.0}
                onChange={(e) => updateSetting('ai', 'daily_budget_limit', parseFloat(e.target.value))}
                margin="normal"
                size="small"
              />
            </TabPanel>

            <TabPanel value={activeTab} index={3}>
              <Typography variant="subtitle2" gutterBottom>
                Conversation
              </Typography>

              <TextField
                fullWidth
                label="Max History Messages"
                type="number"
                value={settings.memory?.max_history || 50}
                onChange={(e) => updateSetting('memory', 'max_history', parseInt(e.target.value))}
                margin="normal"
                size="small"
              />

              <TextField
                fullWidth
                label="Context Window Size"
                type="number"
                value={settings.memory?.context_window || 10}
                onChange={(e) => updateSetting('memory', 'context_window', parseInt(e.target.value))}
                margin="normal"
                size="small"
                helperText="Number of recent messages to include"
              />

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>
                Vector Store
              </Typography>

              <FormControlLabel
                control={
                  <Switch
                    checked={settings.memory?.use_rag ?? true}
                    onChange={(e) => updateSetting('memory', 'use_rag', e.target.checked)}
                  />
                }
                label="Enable RAG (Retrieval-Augmented Generation)"
              />

              <TextField
                fullWidth
                label="Max Relevant Memories"
                type="number"
                value={settings.memory?.max_relevant_memories || 5}
                onChange={(e) => updateSetting('memory', 'max_relevant_memories', parseInt(e.target.value))}
                margin="normal"
                size="small"
              />
            </TabPanel>
          </Box>

          <Divider />

          <Box sx={{ p: 2, display: 'flex', gap: 1 }}>
            <Button
              variant="outlined"
              startIcon={<RestoreIcon />}
              onClick={handleResetSettings}
              disabled={isLoading}
            >
              Reset
            </Button>
            <Box sx={{ flex: 1 }} />
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSaveSettings}
              disabled={isLoading}
            >
              Save
            </Button>
          </Box>
        </Box>
      </Drawer>

      <Snackbar
        open={saveStatus.open}
        autoHideDuration={3000}
        onClose={() => setSaveStatus({ ...saveStatus, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={saveStatus.severity} onClose={() => setSaveStatus({ ...saveStatus, open: false })}>
          {saveStatus.message}
        </Alert>
      </Snackbar>
    </>
  );
}

export default Settings;
