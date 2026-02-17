import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Switch,
  FormControlLabel,
  Chip,
  Grid,
  LinearProgress,
  Alert,
  Fade,
  Zoom,
  Slide,
  Grow,
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Screenshot as ScreenshotIcon,
  BugReport as BugReportIcon,
  Computer as ComputerIcon,
  RemoveRedEye as EyeIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const MonitoringPanel = () => {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [status, setStatus] = useState(null);
  const [currentContext, setCurrentContext] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [detectedApps, setDetectedApps] = useState([]);

  useEffect(() => {
    checkMonitoringStatus();
    const interval = setInterval(checkMonitoringStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const checkMonitoringStatus = async () => {
    try {
      const response = await api.getMonitoringStatus();
      setStatus(response.data);
      setIsMonitoring(response.data.is_running);
      if (response.data.detected_apps) {
        setDetectedApps(response.data.detected_apps);
      }
    } catch (err) {
      console.error('Failed to check monitoring status:', err);
    }
  };

  const handleToggleMonitoring = async () => {
    setLoading(true);
    setError(null);
    try {
      if (isMonitoring) {
        await api.stopMonitoring();
        setIsMonitoring(false);
      } else {
        await api.startMonitoring();
        setIsMonitoring(true);
      }
      await checkMonitoringStatus();
    } catch (err) {
      setError(err.message || 'Failed to toggle monitoring');
    } finally {
      setLoading(false);
    }
  };

  const handleGetContext = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getCurrentContext();
      setCurrentContext(response.data);
    } catch (err) {
      setError(err.message || 'Failed to get context');
    } finally {
      setLoading(false);
    }
  };

  const handleTakeScreenshot = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.takeScreenshot();
      window.open(response.data.screenshot_url, '_blank');
    } catch (err) {
      setError(err.message || 'Failed to take screenshot');
    } finally {
      setLoading(false);
    }
  };

  const getAppIcon = (appName) => {
    if (appName.toLowerCase().includes('burp')) {
      return <BugReportIcon sx={{ mr: 1 }} />;
    }
    return <ComputerIcon sx={{ mr: 1 }} />;
  };

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Card
          sx={{
            background: 'linear-gradient(135deg, rgba(0, 50, 80, 0.6) 0%, rgba(0, 20, 40, 0.8) 100%)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(0, 255, 255, 0.4)',
            boxShadow: isMonitoring 
              ? '0 0 30px rgba(0, 255, 255, 0.4), inset 0 0 20px rgba(0, 255, 255, 0.1)' 
              : '0 0 20px rgba(0, 255, 255, 0.2)',
            borderRadius: 3,
            overflow: 'hidden',
            position: 'relative',
            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
            '&:hover': {
              boxShadow: '0 0 40px rgba(0, 255, 255, 0.5), inset 0 0 30px rgba(0, 255, 255, 0.15)',
              transform: 'translateY(-2px)',
            },
            '&::before': isMonitoring ? {
              content: '""',
              position: 'absolute',
              top: 0,
              left: '-100%',
              width: '100%',
              height: '2px',
              background: 'linear-gradient(90deg, transparent, #00ffff, transparent)',
              animation: 'scan 2s linear infinite',
            } : {},
            '@keyframes scan': {
              '0%': { left: '-100%' },
              '100%': { left: '100%' },
            },
          }}
        >
          <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Slide direction="right" in={true} timeout={600}>
              <Typography 
                variant="h5" 
                sx={{ 
                  color: '#00ffff', 
                  display: 'flex', 
                  alignItems: 'center',
                  fontWeight: 600,
                  textShadow: '0 0 10px rgba(0, 255, 255, 0.5)',
                  letterSpacing: 1,
                }}
              >
                <Box
                  sx={{
                    mr: 1,
                    animation: isMonitoring ? 'pulse 2s ease-in-out infinite' : 'none',
                    '@keyframes pulse': {
                      '0%, 100%': { transform: 'scale(1)', opacity: 1 },
                      '50%': { transform: 'scale(1.1)', opacity: 0.8 },
                    },
                  }}
                >
                  {isMonitoring ? <EyeIcon /> : <VisibilityOffIcon />}
                </Box>
                Screen Monitoring
              </Typography>
            </Slide>
            <Zoom in={true} timeout={800}>
              <FormControlLabel
                control={
                  <Switch
                    checked={isMonitoring}
                    onChange={handleToggleMonitoring}
                    disabled={loading}
                    sx={{
                      '& .MuiSwitch-switchBase.Mui-checked': {
                        color: '#00ffff',
                      },
                      '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': {
                        backgroundColor: '#00ffff',
                      },
                      '& .MuiSwitch-track': {
                        transition: 'all 0.3s ease',
                      },
                    }}
                  />
                }
                label={
                  <Typography
                    sx={{
                      color: isMonitoring ? '#00ffff' : '#00cccc',
                      fontWeight: 500,
                      transition: 'color 0.3s ease',
                    }}
                  >
                    {isMonitoring ? 'Active' : 'Inactive'}
                  </Typography>
                }
              />
            </Zoom>
          </Box>

          {loading && (
            <Fade in={loading}>
              <LinearProgress 
                sx={{ 
                  mb: 2, 
                  backgroundColor: 'rgba(0, 255, 255, 0.2)',
                  '& .MuiLinearProgress-bar': {
                    backgroundColor: '#00ffff',
                    boxShadow: '0 0 10px rgba(0, 255, 255, 0.8)',
                  },
                  height: 3,
                  borderRadius: 2,
                }} 
              />
            </Fade>
          )}

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {status && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="body2" sx={{ color: '#00cccc', mb: 1 }}>
                Capture Interval: {status.capture_interval}s | Last Capture: {status.last_capture_time || 'Never'}
              </Typography>
              {status.captures_count > 0 && (
                <Typography variant="body2" sx={{ color: '#00cccc' }}>
                  Total Captures: {status.captures_count}
                </Typography>
              )}
            </Box>
          )}

          {detectedApps.length > 0 && (
            <Grow in={detectedApps.length > 0} timeout={600}>
              <Box sx={{ mb: 2 }}>
                <Typography 
                  variant="body2" 
                  sx={{ 
                    color: '#00ffff', 
                    mb: 1.5,
                    fontWeight: 500,
                    textShadow: '0 0 5px rgba(0, 255, 255, 0.3)',
                  }}
                >
                  Detected Applications:
                </Typography>
                <Grid container spacing={1}>
                  {detectedApps.map((app, index) => (
                    <Grid item key={index}>
                      <Zoom in={true} timeout={400 + index * 100}>
                        <Chip
                          icon={getAppIcon(app)}
                          label={app}
                          sx={{
                            background: 'linear-gradient(135deg, rgba(0, 255, 255, 0.3) 0%, rgba(0, 200, 200, 0.2) 100%)',
                            color: '#00ffff',
                            border: '1px solid rgba(0, 255, 255, 0.4)',
                            backdropFilter: 'blur(5px)',
                            transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                            '&:hover': {
                              transform: 'translateY(-2px) scale(1.05)',
                              boxShadow: '0 4px 12px rgba(0, 255, 255, 0.4)',
                              border: '1px solid rgba(0, 255, 255, 0.6)',
                            },
                          }}
                        />
                      </Zoom>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            </Grow>
          )}

          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <Zoom in={true} timeout={800}>
              <Button
                variant="outlined"
                startIcon={<ScreenshotIcon />}
                onClick={handleGetContext}
                disabled={!isMonitoring || loading}
                sx={{
                  color: '#00ffff',
                  borderColor: 'rgba(0, 255, 255, 0.4)',
                  backdropFilter: 'blur(10px)',
                  background: 'rgba(0, 255, 255, 0.05)',
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                  '&:hover': {
                    borderColor: '#00ffff',
                    backgroundColor: 'rgba(0, 255, 255, 0.15)',
                    transform: 'translateY(-2px)',
                    boxShadow: '0 4px 12px rgba(0, 255, 255, 0.3)',
                  },
                  '&:active': {
                    transform: 'translateY(0)',
                  },
                }}
              >
                Get Context
              </Button>
            </Zoom>
            <Zoom in={true} timeout={900}>
              <Button
                variant="outlined"
                startIcon={<ScreenshotIcon />}
                onClick={handleTakeScreenshot}
                disabled={!isMonitoring || loading}
                sx={{
                  color: '#00ffff',
                  borderColor: 'rgba(0, 255, 255, 0.4)',
                  backdropFilter: 'blur(10px)',
                  background: 'rgba(0, 255, 255, 0.05)',
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                  '&:hover': {
                    borderColor: '#00ffff',
                    backgroundColor: 'rgba(0, 255, 255, 0.15)',
                    transform: 'translateY(-2px)',
                    boxShadow: '0 4px 12px rgba(0, 255, 255, 0.3)',
                  },
                  '&:active': {
                    transform: 'translateY(0)',
                  },
                }}
              >
                Take Screenshot
              </Button>
            </Zoom>
          </Box>

          {currentContext && (
            <Grow in={Boolean(currentContext)} timeout={600}>
              <Box
                sx={{
                  mt: 3,
                  p: 2.5,
                  background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.4) 0%, rgba(0, 50, 50, 0.3) 100%)',
                  borderRadius: 2,
                  border: '1px solid rgba(0, 255, 255, 0.3)',
                  backdropFilter: 'blur(10px)',
                  boxShadow: 'inset 0 0 20px rgba(0, 255, 255, 0.1)',
                  transition: 'all 0.3s ease',
                  '&:hover': {
                    border: '1px solid rgba(0, 255, 255, 0.5)',
                    boxShadow: 'inset 0 0 25px rgba(0, 255, 255, 0.15)',
                  },
                }}
              >
                <Typography 
                  variant="subtitle2" 
                  sx={{ 
                    color: '#00ffff', 
                    mb: 1.5,
                    fontWeight: 600,
                    textShadow: '0 0 8px rgba(0, 255, 255, 0.5)',
                  }}
                >
                  Current Context:
                </Typography>
                <Typography 
                  variant="body2" 
                  sx={{ 
                    color: '#00cccc', 
                    whiteSpace: 'pre-wrap',
                    lineHeight: 1.7,
                  }}
                >
                  {currentContext.analysis || currentContext.message || 'No context available'}
                </Typography>
              </Box>
            </Grow>
          )}
        </CardContent>
      </Card>
    </Box>
    </Fade>
  );
};

export default MonitoringPanel;
