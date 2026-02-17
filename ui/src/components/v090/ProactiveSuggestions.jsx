import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  IconButton,
  Chip,
  Stack,
  LinearProgress,
  Alert,
  Fade,
  Zoom,
  Slide,
  Collapse,
  Tooltip,
} from '@mui/material';
import {
  Lightbulb as LightbulbIcon,
  PlayArrow as PlayIcon,
  Close as CloseIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingIcon,
  Code as CodeIcon,
  Security as SecurityIcon,
  YouTube as YouTubeIcon,
  Psychology as BrainIcon,
  AutoAwesome as SparkleIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const ProactiveSuggestions = () => {
  const [suggestions, setSuggestions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [executing, setExecuting] = useState({});

  useEffect(() => {
    fetchSuggestions();
    const interval = setInterval(fetchSuggestions, 60000);
    return () => clearInterval(interval);
  }, []);

  const fetchSuggestions = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getProactiveSuggestions();
      setSuggestions(response.data.suggestions || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch suggestions');
    } finally {
      setLoading(false);
    }
  };

  const handleExecute = async (suggestionId) => {
    setExecuting((prev) => ({ ...prev, [suggestionId]: true }));
    setError(null);
    try {
      await api.executeProactiveSuggestion(suggestionId);
      await fetchSuggestions();
    } catch (err) {
      setError(err.message || 'Failed to execute suggestion');
    } finally {
      setExecuting((prev) => ({ ...prev, [suggestionId]: false }));
    }
  };

  const handleDismiss = (suggestionId) => {
    setSuggestions((prev) => prev.filter((s) => s.id !== suggestionId));
  };

  const getCategoryIcon = (category) => {
    const icons = {
      bugbounty: <SecurityIcon />,
      youtube: <YouTubeIcon />,
      coding: <CodeIcon />,
      learning: <BrainIcon />,
      productivity: <TrendingIcon />,
      default: <LightbulbIcon />,
    };
    return icons[category?.toLowerCase()] || icons.default;
  };

  const getCategoryColor = (category) => {
    const colors = {
      bugbounty: { main: '#ff5722', glow: 'rgba(255, 87, 34, 0.4)' },
      youtube: { main: '#ff0000', glow: 'rgba(255, 0, 0, 0.4)' },
      coding: { main: '#4caf50', glow: 'rgba(76, 175, 80, 0.4)' },
      learning: { main: '#9c27b0', glow: 'rgba(156, 39, 176, 0.4)' },
      productivity: { main: '#2196f3', glow: 'rgba(33, 150, 243, 0.4)' },
      default: { main: '#00ffff', glow: 'rgba(0, 255, 255, 0.4)' },
    };
    return colors[category?.toLowerCase()] || colors.default;
  };

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Card
          sx={{
            background: 'linear-gradient(135deg, rgba(80, 0, 80, 0.4) 0%, rgba(0, 20, 60, 0.6) 100%)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(156, 39, 176, 0.4)',
            boxShadow: '0 0 30px rgba(156, 39, 176, 0.3), inset 0 0 20px rgba(156, 39, 176, 0.1)',
            borderRadius: 3,
            overflow: 'hidden',
            position: 'relative',
            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
            '&:hover': {
              boxShadow: '0 0 40px rgba(156, 39, 176, 0.5), inset 0 0 30px rgba(156, 39, 176, 0.15)',
              transform: 'translateY(-2px)',
            },
            '&::before': {
              content: '""',
              position: 'absolute',
              top: '-50%',
              right: '-50%',
              width: '200%',
              height: '200%',
              background: 'radial-gradient(circle, rgba(156, 39, 176, 0.1) 0%, transparent 70%)',
              animation: 'rotate 20s linear infinite',
            },
            '@keyframes rotate': {
              '0%': { transform: 'rotate(0deg)' },
              '100%': { transform: 'rotate(360deg)' },
            },
          }}
        >
          <CardContent sx={{ position: 'relative', zIndex: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
              <Slide direction="right" in={true} timeout={600}>
                <Typography
                  variant="h5"
                  sx={{
                    color: '#e1bee7',
                    display: 'flex',
                    alignItems: 'center',
                    fontWeight: 600,
                    textShadow: '0 0 10px rgba(156, 39, 176, 0.8)',
                    letterSpacing: 1,
                  }}
                >
                  <Box
                    sx={{
                      mr: 1,
                      animation: 'pulse 2s ease-in-out infinite',
                      '@keyframes pulse': {
                        '0%, 100%': { transform: 'scale(1)', opacity: 1 },
                        '50%': { transform: 'scale(1.2)', opacity: 0.7 },
                      },
                    }}
                  >
                    <SparkleIcon />
                  </Box>
                  Proactive Suggestions
                </Typography>
              </Slide>
              <Zoom in={true} timeout={800}>
                <Tooltip title="Refresh Suggestions">
                  <IconButton
                    onClick={fetchSuggestions}
                    disabled={loading}
                    sx={{
                      color: '#e1bee7',
                      backgroundColor: 'rgba(156, 39, 176, 0.2)',
                      border: '1px solid rgba(156, 39, 176, 0.3)',
                      transition: 'all 0.3s ease',
                      '&:hover': {
                        backgroundColor: 'rgba(156, 39, 176, 0.3)',
                        transform: 'rotate(180deg)',
                        boxShadow: '0 0 15px rgba(156, 39, 176, 0.5)',
                      },
                    }}
                  >
                    <RefreshIcon />
                  </IconButton>
                </Tooltip>
              </Zoom>
            </Box>

            {loading && (
              <Fade in={loading}>
                <LinearProgress
                  sx={{
                    mb: 2,
                    backgroundColor: 'rgba(156, 39, 176, 0.2)',
                    '& .MuiLinearProgress-bar': {
                      backgroundColor: '#9c27b0',
                      boxShadow: '0 0 10px rgba(156, 39, 176, 0.8)',
                    },
                    height: 3,
                    borderRadius: 2,
                  }}
                />
              </Fade>
            )}

            {error && (
              <Collapse in={Boolean(error)}>
                <Alert severity="error" sx={{ mb: 2 }}>
                  {error}
                </Alert>
              </Collapse>
            )}

            {suggestions.length === 0 && !loading && (
              <Fade in={true} timeout={600}>
                <Box
                  sx={{
                    textAlign: 'center',
                    py: 4,
                    color: '#ba68c8',
                  }}
                >
                  <LightbulbIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                  <Typography variant="body1">
                    Ji boss! Abhi koi naya suggestion nahi hai. Thodi der mein check karta hoon! 💡
                  </Typography>
                </Box>
              </Fade>
            )}

            <Stack spacing={2}>
              {suggestions.map((suggestion, index) => {
                const categoryColor = getCategoryColor(suggestion.category);
                return (
                  <Zoom key={suggestion.id} in={true} timeout={400 + index * 100}>
                    <Card
                      sx={{
                        background: `linear-gradient(135deg, rgba(0, 0, 0, 0.4) 0%, ${categoryColor.glow} 100%)`,
                        backdropFilter: 'blur(10px)',
                        border: `1px solid ${categoryColor.main}40`,
                        borderRadius: 2,
                        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                        position: 'relative',
                        overflow: 'hidden',
                        '&:hover': {
                          transform: 'translateX(5px)',
                          boxShadow: `0 4px 20px ${categoryColor.glow}`,
                          border: `1px solid ${categoryColor.main}80`,
                        },
                        '&::before': {
                          content: '""',
                          position: 'absolute',
                          left: 0,
                          top: 0,
                          width: '4px',
                          height: '100%',
                          background: categoryColor.main,
                          boxShadow: `0 0 10px ${categoryColor.main}`,
                        },
                      }}
                    >
                      <CardContent>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', flex: 1 }}>
                            <Box
                              sx={{
                                mr: 1.5,
                                color: categoryColor.main,
                                display: 'flex',
                                alignItems: 'center',
                              }}
                            >
                              {getCategoryIcon(suggestion.category)}
                            </Box>
                            <Box sx={{ flex: 1 }}>
                              <Typography
                                variant="subtitle1"
                                sx={{
                                  color: '#fff',
                                  fontWeight: 600,
                                  mb: 0.5,
                                }}
                              >
                                {suggestion.title}
                              </Typography>
                              <Typography
                                variant="body2"
                                sx={{
                                  color: 'rgba(255, 255, 255, 0.7)',
                                  lineHeight: 1.6,
                                }}
                              >
                                {suggestion.description}
                              </Typography>
                            </Box>
                          </Box>
                          <IconButton
                            size="small"
                            onClick={() => handleDismiss(suggestion.id)}
                            sx={{
                              color: 'rgba(255, 255, 255, 0.5)',
                              transition: 'all 0.2s ease',
                              '&:hover': {
                                color: '#ff5252',
                                transform: 'rotate(90deg)',
                              },
                            }}
                          >
                            <CloseIcon fontSize="small" />
                          </IconButton>
                        </Box>

                        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                          {suggestion.confidence && (
                            <Chip
                              label={`${Math.round(suggestion.confidence * 100)}% confident`}
                              size="small"
                              sx={{
                                backgroundColor: 'rgba(76, 175, 80, 0.2)',
                                color: '#81c784',
                                border: '1px solid rgba(76, 175, 80, 0.3)',
                                fontSize: '0.75rem',
                              }}
                            />
                          )}
                          {suggestion.category && (
                            <Chip
                              label={suggestion.category}
                              size="small"
                              sx={{
                                backgroundColor: `${categoryColor.main}20`,
                                color: categoryColor.main,
                                border: `1px solid ${categoryColor.main}40`,
                                fontSize: '0.75rem',
                                textTransform: 'uppercase',
                              }}
                            />
                          )}
                          <Box sx={{ flex: 1 }} />
                          <Button
                            variant="contained"
                            startIcon={executing[suggestion.id] ? null : <PlayIcon />}
                            onClick={() => handleExecute(suggestion.id)}
                            disabled={executing[suggestion.id]}
                            size="small"
                            sx={{
                              background: `linear-gradient(135deg, ${categoryColor.main} 0%, ${categoryColor.main}CC 100%)`,
                              color: '#fff',
                              fontWeight: 600,
                              boxShadow: `0 0 15px ${categoryColor.glow}`,
                              transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                              '&:hover': {
                                background: `linear-gradient(135deg, ${categoryColor.main}EE 0%, ${categoryColor.main} 100%)`,
                                boxShadow: `0 0 20px ${categoryColor.main}80`,
                                transform: 'scale(1.05)',
                              },
                              '&:active': {
                                transform: 'scale(0.98)',
                              },
                            }}
                          >
                            {executing[suggestion.id] ? 'Executing...' : 'Execute'}
                          </Button>
                        </Box>
                      </CardContent>
                    </Card>
                  </Zoom>
                );
              })}
            </Stack>
          </CardContent>
        </Card>
      </Box>
    </Fade>
  );
};

export default ProactiveSuggestions;
