import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Slider,
  Switch,
  FormControlLabel,
  Alert,
  Fade,
  Zoom,
  Slide,
  Collapse,
  Divider,
  Chip,
  Stack,
} from '@mui/material';
import {
  Face as FaceIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  EmojiEmotions as EmojiIcon,
  Language as LanguageIcon,
  Psychology as BrainIcon,
  VolumeUp as VolumeIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const PersonalitySettings = () => {
  const [settings, setSettings] = useState({
    tone: 'friendly',
    language_mix: 70,
    use_emojis: true,
    humor_level: 50,
    motivational_mode: true,
    proactive_frequency: 3,
  });
  const [originalSettings, setOriginalSettings] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    fetchPersonalitySettings();
  }, []);

  const fetchPersonalitySettings = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getPersonalitySettings();
      setSettings(response.data);
      setOriginalSettings(response.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch settings');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setLoading(true);
    setError(null);
    setSuccess(false);
    try {
      await api.updatePersonalitySettings(settings);
      setOriginalSettings(settings);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err.message || 'Failed to save settings');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    if (originalSettings) {
      setSettings(originalSettings);
    }
  };

  const hasChanges = JSON.stringify(settings) !== JSON.stringify(originalSettings);

  const toneOptions = [
    { value: 'friendly', label: 'Friendly', emoji: '😊', color: '#4caf50' },
    { value: 'professional', label: 'Professional', emoji: '💼', color: '#2196f3' },
    { value: 'casual', label: 'Casual', emoji: '😎', color: '#ff9800' },
    { value: 'motivational', label: 'Motivational', emoji: '💪', color: '#9c27b0' },
  ];

  const getPreviewMessage = () => {
    const messages = {
      friendly: "Ji boss! Kaise ho? Aaj kya plan hai? Main ready hoon help karne! 😊",
      professional: "Hello. How may I assist you today? I'm prepared to handle your tasks efficiently.",
      casual: "Yo boss! What's up? Kya scene hai aaj? Let's do something cool! 😎",
      motivational: "Boss! You're unstoppable! Aaj bhi ek aur din conquer karenge! Let's go! 💪🔥",
    };
    return messages[settings.tone] || messages.friendly;
  };

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Card
          sx={{
            background: 'linear-gradient(135deg, rgba(233, 30, 99, 0.3) 0%, rgba(156, 39, 176, 0.3) 100%)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(233, 30, 99, 0.4)',
            boxShadow: '0 0 30px rgba(233, 30, 99, 0.3), inset 0 0 20px rgba(233, 30, 99, 0.1)',
            borderRadius: 3,
            overflow: 'hidden',
            position: 'relative',
            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
            '&:hover': {
              boxShadow: '0 0 40px rgba(233, 30, 99, 0.5), inset 0 0 30px rgba(233, 30, 99, 0.15)',
              transform: 'translateY(-2px)',
            },
          }}
        >
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
              <Slide direction="right" in={true} timeout={600}>
                <Typography
                  variant="h5"
                  sx={{
                    color: '#f48fb1',
                    display: 'flex',
                    alignItems: 'center',
                    fontWeight: 600,
                    textShadow: '0 0 10px rgba(233, 30, 99, 0.8)',
                    letterSpacing: 1,
                  }}
                >
                  <Box
                    sx={{
                      mr: 1,
                      animation: 'wiggle 2s ease-in-out infinite',
                      '@keyframes wiggle': {
                        '0%, 100%': { transform: 'rotate(0deg)' },
                        '25%': { transform: 'rotate(-10deg)' },
                        '75%': { transform: 'rotate(10deg)' },
                      },
                    }}
                  >
                    <FaceIcon />
                  </Box>
                  Personality Settings
                </Typography>
              </Slide>
              <Zoom in={true} timeout={800}>
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={fetchPersonalitySettings}
                  disabled={loading}
                  sx={{
                    color: '#f48fb1',
                    borderColor: 'rgba(233, 30, 99, 0.3)',
                    '&:hover': {
                      borderColor: '#e91e63',
                      backgroundColor: 'rgba(233, 30, 99, 0.1)',
                    },
                  }}
                >
                  Refresh
                </Button>
              </Zoom>
            </Box>

            {error && (
              <Collapse in={Boolean(error)}>
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
                  {error}
                </Alert>
              </Collapse>
            )}

            {success && (
              <Collapse in={success}>
                <Alert severity="success" sx={{ mb: 2 }}>
                  Boss! Settings save ho gayi! 🎉
                </Alert>
              </Collapse>
            )}

            <Stack spacing={3}>
              <Zoom in={true} timeout={600}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <EmojiIcon sx={{ mr: 1, color: '#f48fb1' }} />
                    <Typography variant="subtitle1" sx={{ color: '#f48fb1', fontWeight: 600 }}>
                      Conversation Tone
                    </Typography>
                  </Box>
                  <Stack direction="row" spacing={1} flexWrap="wrap" gap={1}>
                    {toneOptions.map((option) => (
                      <Chip
                        key={option.value}
                        label={`${option.emoji} ${option.label}`}
                        onClick={() => setSettings({ ...settings, tone: option.value })}
                        sx={{
                          backgroundColor:
                            settings.tone === option.value
                              ? `${option.color}40`
                              : 'rgba(0, 0, 0, 0.3)',
                          color: settings.tone === option.value ? option.color : 'rgba(255, 255, 255, 0.7)',
                          border:
                            settings.tone === option.value
                              ? `2px solid ${option.color}`
                              : '1px solid rgba(255, 255, 255, 0.2)',
                          fontSize: '0.95rem',
                          padding: '20px 12px',
                          transition: 'all 0.3s ease',
                          cursor: 'pointer',
                          '&:hover': {
                            backgroundColor: `${option.color}30`,
                            transform: 'scale(1.05)',
                            boxShadow: `0 4px 12px ${option.color}40`,
                          },
                        }}
                      />
                    ))}
                  </Stack>
                </Box>
              </Zoom>

              <Zoom in={true} timeout={700}>
                <Box
                  sx={{
                    p: 2.5,
                    background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.4) 0%, rgba(233, 30, 99, 0.1) 100%)',
                    borderRadius: 2,
                    border: '1px solid rgba(233, 30, 99, 0.3)',
                    backdropFilter: 'blur(10px)',
                  }}
                >
                  <Typography variant="body2" sx={{ color: '#f48fb1', mb: 1, fontWeight: 500 }}>
                    Preview:
                  </Typography>
                  <Typography
                    variant="body1"
                    sx={{
                      color: '#fff',
                      fontStyle: 'italic',
                      lineHeight: 1.7,
                    }}
                  >
                    {getPreviewMessage()}
                  </Typography>
                </Box>
              </Zoom>

              <Divider sx={{ borderColor: 'rgba(233, 30, 99, 0.2)' }} />

              <Zoom in={true} timeout={800}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <LanguageIcon sx={{ mr: 1, color: '#f48fb1' }} />
                    <Typography variant="subtitle1" sx={{ color: '#f48fb1', fontWeight: 600 }}>
                      Hindi-English Mix Level
                    </Typography>
                  </Box>
                  <Box sx={{ px: 2 }}>
                    <Slider
                      value={settings.language_mix}
                      onChange={(e, value) => setSettings({ ...settings, language_mix: value })}
                      min={0}
                      max={100}
                      valueLabelDisplay="auto"
                      valueLabelFormat={(value) => `${value}% Hindi`}
                      sx={{
                        color: '#e91e63',
                        '& .MuiSlider-thumb': {
                          boxShadow: '0 0 10px rgba(233, 30, 99, 0.8)',
                        },
                        '& .MuiSlider-track': {
                          background: 'linear-gradient(90deg, #2196f3 0%, #e91e63 100%)',
                        },
                      }}
                    />
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
                      <Typography variant="caption" sx={{ color: '#90caf9' }}>
                        Full English
                      </Typography>
                      <Typography variant="caption" sx={{ color: '#f48fb1' }}>
                        Full Hindi
                      </Typography>
                    </Box>
                  </Box>
                </Box>
              </Zoom>

              <Zoom in={true} timeout={900}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <BrainIcon sx={{ mr: 1, color: '#f48fb1' }} />
                    <Typography variant="subtitle1" sx={{ color: '#f48fb1', fontWeight: 600 }}>
                      Humor Level
                    </Typography>
                  </Box>
                  <Box sx={{ px: 2 }}>
                    <Slider
                      value={settings.humor_level}
                      onChange={(e, value) => setSettings({ ...settings, humor_level: value })}
                      min={0}
                      max={100}
                      valueLabelDisplay="auto"
                      valueLabelFormat={(value) => `${value}%`}
                      sx={{
                        color: '#ff9800',
                        '& .MuiSlider-thumb': {
                          boxShadow: '0 0 10px rgba(255, 152, 0, 0.8)',
                        },
                        '& .MuiSlider-track': {
                          background: 'linear-gradient(90deg, #9e9e9e 0%, #ff9800 100%)',
                        },
                      }}
                    />
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
                      <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.6)' }}>
                        Serious 😐
                      </Typography>
                      <Typography variant="caption" sx={{ color: '#ff9800' }}>
                        Funny 😂
                      </Typography>
                    </Box>
                  </Box>
                </Box>
              </Zoom>

              <Zoom in={true} timeout={1000}>
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <VolumeIcon sx={{ mr: 1, color: '#f48fb1' }} />
                    <Typography variant="subtitle1" sx={{ color: '#f48fb1', fontWeight: 600 }}>
                      Proactive Frequency (checks per hour)
                    </Typography>
                  </Box>
                  <Box sx={{ px: 2 }}>
                    <Slider
                      value={settings.proactive_frequency}
                      onChange={(e, value) => setSettings({ ...settings, proactive_frequency: value })}
                      min={1}
                      max={10}
                      step={1}
                      marks
                      valueLabelDisplay="auto"
                      valueLabelFormat={(value) => `${value}x/hr`}
                      sx={{
                        color: '#9c27b0',
                        '& .MuiSlider-thumb': {
                          boxShadow: '0 0 10px rgba(156, 39, 176, 0.8)',
                        },
                        '& .MuiSlider-track': {
                          background: 'linear-gradient(90deg, #4caf50 0%, #9c27b0 100%)',
                        },
                      }}
                    />
                  </Box>
                </Box>
              </Zoom>

              <Divider sx={{ borderColor: 'rgba(233, 30, 99, 0.2)' }} />

              <Zoom in={true} timeout={1100}>
                <Box>
                  <Stack spacing={1.5}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={settings.use_emojis}
                          onChange={(e) => setSettings({ ...settings, use_emojis: e.target.checked })}
                          sx={{
                            '& .MuiSwitch-switchBase.Mui-checked': {
                              color: '#e91e63',
                            },
                            '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {
                              backgroundColor: '#e91e63',
                            },
                          }}
                        />
                      }
                      label={
                        <Typography sx={{ color: '#f48fb1' }}>
                          Use Emojis in Responses 😊🎉
                        </Typography>
                      }
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={settings.motivational_mode}
                          onChange={(e) => setSettings({ ...settings, motivational_mode: e.target.checked })}
                          sx={{
                            '& .MuiSwitch-switchBase.Mui-checked': {
                              color: '#e91e63',
                            },
                            '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {
                              backgroundColor: '#e91e63',
                            },
                          }}
                        />
                      }
                      label={
                        <Typography sx={{ color: '#f48fb1' }}>
                          Motivational Mode (Extra encouragement) 💪
                        </Typography>
                      }
                    />
                  </Stack>
                </Box>
              </Zoom>

              <Zoom in={true} timeout={1200}>
                <Box sx={{ display: 'flex', gap: 2, pt: 2 }}>
                  <Button
                    variant="outlined"
                    onClick={handleReset}
                    disabled={!hasChanges || loading}
                    fullWidth
                    sx={{
                      color: '#f48fb1',
                      borderColor: 'rgba(233, 30, 99, 0.3)',
                      '&:hover': {
                        borderColor: '#e91e63',
                        backgroundColor: 'rgba(233, 30, 99, 0.1)',
                      },
                    }}
                  >
                    Reset
                  </Button>
                  <Button
                    variant="contained"
                    startIcon={<SaveIcon />}
                    onClick={handleSave}
                    disabled={!hasChanges || loading}
                    fullWidth
                    sx={{
                      background: hasChanges
                        ? 'linear-gradient(135deg, #e91e63 0%, #9c27b0 100%)'
                        : 'rgba(158, 158, 158, 0.3)',
                      boxShadow: hasChanges ? '0 0 20px rgba(233, 30, 99, 0.5)' : 'none',
                      transition: 'all 0.3s ease',
                      '&:hover': hasChanges
                        ? {
                            background: 'linear-gradient(135deg, #c2185b 0%, #7b1fa2 100%)',
                            boxShadow: '0 0 25px rgba(233, 30, 99, 0.6)',
                            transform: 'scale(1.02)',
                          }
                        : {},
                    }}
                  >
                    {loading ? 'Saving...' : 'Save Changes'}
                  </Button>
                </Box>
              </Zoom>
            </Stack>
          </CardContent>
        </Card>
      </Box>
    </Fade>
  );
};

export default PersonalitySettings;
