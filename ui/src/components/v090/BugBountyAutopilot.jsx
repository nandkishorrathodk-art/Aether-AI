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
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  TrendingUp as TrendingIcon,
  AttachMoney as MoneyIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const BugBountyAutopilot = () => {
  const [scanStatus, setScanStatus] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    checkScanStatus();
    const interval = setInterval(checkScanStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const checkScanStatus = async () => {
    try {
      const response = await api.getBugBountyStatus();
      setScanStatus(response.data);
      setIsScanning(response.data.is_running);
      if (response.data.findings) {
        setFindings(response.data.findings);
      }
    } catch (err) {
      console.error('Failed to check scan status:', err);
    }
  };

  const handleStartScan = async () => {
    setLoading(true);
    setError(null);
    try {
      await api.startBugBountyScan();
      setIsScanning(true);
      await checkScanStatus();
    } catch (err) {
      setError(err.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const handleStopScan = async () => {
    setLoading(true);
    setError(null);
    try {
      await api.stopBugBountyScan();
      setIsScanning(false);
      await checkScanStatus();
    } catch (err) {
      setError(err.message || 'Failed to stop scan');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.generateBugBountyReport();
      window.open(response.data.report_url, '_blank');
    } catch (err) {
      setError(err.message || 'Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityIcon = (severity) => {
    const icons = {
      critical: <ErrorIcon sx={{ color: '#f44336' }} />,
      high: <WarningIcon sx={{ color: '#ff9800' }} />,
      medium: <WarningIcon sx={{ color: '#ffc107' }} />,
      low: <InfoIcon sx={{ color: '#2196f3' }} />,
      info: <InfoIcon sx={{ color: '#00bcd4' }} />,
    };
    return icons[severity?.toLowerCase()] || icons.info;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: { main: '#f44336', glow: 'rgba(244, 67, 54, 0.4)' },
      high: { main: '#ff9800', glow: 'rgba(255, 152, 0, 0.4)' },
      medium: { main: '#ffc107', glow: 'rgba(255, 193, 7, 0.4)' },
      low: { main: '#2196f3', glow: 'rgba(33, 150, 243, 0.4)' },
      info: { main: '#00bcd4', glow: 'rgba(0, 188, 212, 0.4)' },
    };
    return colors[severity?.toLowerCase()] || colors.info;
  };

  const calculateTotalPayout = () => {
    return findings.reduce((total, finding) => total + (finding.estimated_payout || 0), 0);
  };

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Card
          sx={{
            background: 'linear-gradient(135deg, rgba(244, 67, 54, 0.3) 0%, rgba(233, 30, 99, 0.3) 100%)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(244, 67, 54, 0.4)',
            boxShadow: isScanning
              ? '0 0 30px rgba(244, 67, 54, 0.5), inset 0 0 20px rgba(244, 67, 54, 0.2)'
              : '0 0 30px rgba(244, 67, 54, 0.3), inset 0 0 20px rgba(244, 67, 54, 0.1)',
            borderRadius: 3,
            overflow: 'hidden',
            position: 'relative',
            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
            '&:hover': {
              boxShadow: '0 0 40px rgba(244, 67, 54, 0.5), inset 0 0 30px rgba(244, 67, 54, 0.15)',
              transform: 'translateY(-2px)',
            },
            '&::before': isScanning ? {
              content: '""',
              position: 'absolute',
              top: 0,
              left: '-100%',
              width: '100%',
              height: '100%',
              background: 'linear-gradient(90deg, transparent, rgba(244, 67, 54, 0.3), transparent)',
              animation: 'scanning 3s linear infinite',
            } : {},
            '@keyframes scanning': {
              '0%': { left: '-100%' },
              '100%': { left: '100%' },
            },
          }}
        >
          <CardContent sx={{ position: 'relative', zIndex: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
              <Slide direction="right" in={true} timeout={600}>
                <Typography
                  variant="h5"
                  sx={{
                    color: '#ef5350',
                    display: 'flex',
                    alignItems: 'center',
                    fontWeight: 600,
                    textShadow: '0 0 10px rgba(244, 67, 54, 0.8)',
                    letterSpacing: 1,
                  }}
                >
                  <Box
                    sx={{
                      mr: 1,
                      animation: isScanning ? 'spin 2s linear infinite' : 'none',
                      '@keyframes spin': {
                        '0%': { transform: 'rotate(0deg)' },
                        '100%': { transform: 'rotate(360deg)' },
                      },
                    }}
                  >
                    <BugIcon />
                  </Box>
                  Bug Bounty Autopilot
                </Typography>
              </Slide>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Zoom in={true} timeout={800}>
                  <Tooltip title="Refresh Status">
                    <IconButton
                      onClick={checkScanStatus}
                      disabled={loading}
                      sx={{
                        color: '#ef5350',
                        backgroundColor: 'rgba(244, 67, 54, 0.2)',
                        border: '1px solid rgba(244, 67, 54, 0.3)',
                        transition: 'all 0.3s ease',
                        '&:hover': {
                          backgroundColor: 'rgba(244, 67, 54, 0.3)',
                          transform: 'rotate(180deg)',
                          boxShadow: '0 0 15px rgba(244, 67, 54, 0.5)',
                        },
                      }}
                    >
                      <RefreshIcon />
                    </IconButton>
                  </Tooltip>
                </Zoom>
                {isScanning ? (
                  <Zoom in={true} timeout={900}>
                    <Button
                      variant="contained"
                      startIcon={<StopIcon />}
                      onClick={handleStopScan}
                      disabled={loading}
                      sx={{
                        background: 'linear-gradient(135deg, #f44336 0%, #e91e63 100%)',
                        boxShadow: '0 0 20px rgba(244, 67, 54, 0.5)',
                        animation: 'pulse 1.5s ease-in-out infinite',
                        '@keyframes pulse': {
                          '0%, 100%': { boxShadow: '0 0 20px rgba(244, 67, 54, 0.5)' },
                          '50%': { boxShadow: '0 0 30px rgba(244, 67, 54, 0.8)' },
                        },
                        '&:hover': {
                          background: 'linear-gradient(135deg, #e91e63 0%, #f44336 100%)',
                        },
                      }}
                    >
                      Stop Scan
                    </Button>
                  </Zoom>
                ) : (
                  <Zoom in={true} timeout={900}>
                    <Button
                      variant="contained"
                      startIcon={<PlayIcon />}
                      onClick={handleStartScan}
                      disabled={loading}
                      sx={{
                        background: 'linear-gradient(135deg, #4caf50 0%, #8bc34a 100%)',
                        boxShadow: '0 0 20px rgba(76, 175, 80, 0.4)',
                        transition: 'all 0.3s ease',
                        '&:hover': {
                          background: 'linear-gradient(135deg, #66bb6a 0%, #9ccc65 100%)',
                          boxShadow: '0 0 25px rgba(76, 175, 80, 0.6)',
                          transform: 'scale(1.05)',
                        },
                      }}
                    >
                      Start Scan
                    </Button>
                  </Zoom>
                )}
              </Box>
            </Box>

            {loading && (
              <Fade in={loading}>
                <LinearProgress
                  sx={{
                    mb: 2,
                    backgroundColor: 'rgba(244, 67, 54, 0.2)',
                    '& .MuiLinearProgress-bar': {
                      backgroundColor: '#f44336',
                      boxShadow: '0 0 10px rgba(244, 67, 54, 0.8)',
                    },
                    height: 3,
                    borderRadius: 2,
                  }}
                />
              </Fade>
            )}

            {error && (
              <Collapse in={Boolean(error)}>
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
                  {error}
                </Alert>
              </Collapse>
            )}

            {scanStatus && (
              <Fade in={true} timeout={600}>
                <Box
                  sx={{
                    mb: 3,
                    p: 2.5,
                    background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.4) 0%, rgba(244, 67, 54, 0.2) 100%)',
                    borderRadius: 2,
                    border: '1px solid rgba(244, 67, 54, 0.3)',
                    backdropFilter: 'blur(10px)',
                  }}
                >
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                    <Box>
                      <Typography variant="body2" sx={{ color: '#ef9a9a', mb: 0.5 }}>
                        Status: {isScanning ? 'Scanning...' : 'Idle'}
                      </Typography>
                      {scanStatus.target && (
                        <Typography variant="body2" sx={{ color: '#ef9a9a' }}>
                          Target: {scanStatus.target}
                        </Typography>
                      )}
                    </Box>
                    <Chip
                      icon={<TrendingIcon />}
                      label={`${findings.length} Findings`}
                      sx={{
                        backgroundColor: 'rgba(76, 175, 80, 0.2)',
                        color: '#81c784',
                        border: '1px solid rgba(76, 175, 80, 0.3)',
                        fontWeight: 600,
                      }}
                    />
                  </Box>

                  {isScanning && scanStatus.progress !== undefined && (
                    <Box>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                        <Typography variant="body2" sx={{ color: '#ef9a9a' }}>
                          Progress
                        </Typography>
                        <Typography variant="body2" sx={{ color: '#ef9a9a', fontWeight: 600 }}>
                          {scanStatus.progress}%
                        </Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={scanStatus.progress}
                        sx={{
                          height: 8,
                          borderRadius: 4,
                          backgroundColor: 'rgba(244, 67, 54, 0.2)',
                          '& .MuiLinearProgress-bar': {
                            background: 'linear-gradient(90deg, #f44336 0%, #ff9800 100%)',
                            boxShadow: '0 0 10px rgba(244, 67, 54, 0.8)',
                            borderRadius: 4,
                          },
                        }}
                      />
                    </Box>
                  )}

                  {calculateTotalPayout() > 0 && (
                    <Box
                      sx={{
                        mt: 2,
                        p: 1.5,
                        background: 'linear-gradient(135deg, rgba(255, 215, 0, 0.2) 0%, rgba(255, 193, 7, 0.2) 100%)',
                        borderRadius: 1,
                        border: '1px solid rgba(255, 215, 0, 0.3)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <MoneyIcon sx={{ color: '#ffd700', mr: 1 }} />
                      <Typography variant="h6" sx={{ color: '#ffd700', fontWeight: 700 }}>
                        Estimated Payout: ${calculateTotalPayout().toLocaleString()}
                      </Typography>
                    </Box>
                  )}
                </Box>
              </Fade>
            )}

            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography
                variant="subtitle1"
                sx={{
                  color: '#ef5350',
                  fontWeight: 600,
                  textShadow: '0 0 5px rgba(244, 67, 54, 0.5)',
                }}
              >
                Vulnerabilities Found
              </Typography>
              {findings.length > 0 && (
                <Button
                  size="small"
                  startIcon={<DownloadIcon />}
                  onClick={handleGenerateReport}
                  disabled={loading}
                  sx={{
                    color: '#ef5350',
                    borderColor: 'rgba(244, 67, 54, 0.3)',
                    '&:hover': {
                      borderColor: '#f44336',
                      backgroundColor: 'rgba(244, 67, 54, 0.1)',
                    },
                  }}
                >
                  Generate Report
                </Button>
              )}
            </Box>

            {findings.length === 0 ? (
              <Fade in={true} timeout={600}>
                <Box
                  sx={{
                    textAlign: 'center',
                    py: 4,
                    color: '#ef9a9a',
                  }}
                >
                  <SecurityIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                  <Typography variant="body1">
                    {isScanning
                      ? 'Boss! Scan chal raha hai... bugs dhund raha hoon! 🔍'
                      : 'Abhi koi vulnerability nahi mili. Scan start karo! 🚀'}
                  </Typography>
                </Box>
              </Fade>
            ) : (
              <List sx={{ maxHeight: 400, overflow: 'auto' }}>
                {findings.map((finding, index) => {
                  const severityColor = getSeverityColor(finding.severity);
                  return (
                    <Zoom key={index} in={true} timeout={400 + index * 100}>
                      <Box>
                        <ListItem
                          sx={{
                            background: `linear-gradient(135deg, rgba(0, 0, 0, 0.3) 0%, ${severityColor.glow} 100%)`,
                            backdropFilter: 'blur(10px)',
                            border: `1px solid ${severityColor.main}40`,
                            borderRadius: 2,
                            mb: 1,
                            transition: 'all 0.3s ease',
                            '&:hover': {
                              transform: 'translateX(5px)',
                              boxShadow: `0 4px 20px ${severityColor.glow}`,
                            },
                          }}
                        >
                          <ListItemIcon>{getSeverityIcon(finding.severity)}</ListItemIcon>
                          <ListItemText
                            primary={
                              <Typography sx={{ color: '#fff', fontWeight: 600 }}>
                                {finding.title}
                              </Typography>
                            }
                            secondary={
                              <Box>
                                <Typography variant="body2" sx={{ color: 'rgba(255, 255, 255, 0.7)', mb: 0.5 }}>
                                  {finding.description}
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                                  <Chip
                                    label={finding.severity}
                                    size="small"
                                    sx={{
                                      backgroundColor: `${severityColor.main}20`,
                                      color: severityColor.main,
                                      border: `1px solid ${severityColor.main}40`,
                                      fontSize: '0.7rem',
                                      textTransform: 'uppercase',
                                      fontWeight: 600,
                                    }}
                                  />
                                  {finding.estimated_payout && (
                                    <Chip
                                      icon={<MoneyIcon />}
                                      label={`$${finding.estimated_payout.toLocaleString()}`}
                                      size="small"
                                      sx={{
                                        backgroundColor: 'rgba(255, 215, 0, 0.2)',
                                        color: '#ffd700',
                                        border: '1px solid rgba(255, 215, 0, 0.3)',
                                        fontSize: '0.7rem',
                                        fontWeight: 600,
                                      }}
                                    />
                                  )}
                                </Box>
                              </Box>
                            }
                          />
                        </ListItem>
                      </Box>
                    </Zoom>
                  );
                })}
              </List>
            )}
          </CardContent>
        </Card>
      </Box>
    </Fade>
  );
};

export default BugBountyAutopilot;
