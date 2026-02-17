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
  Divider,
  Grid,
} from '@mui/material';
import {
  Assessment as ReportIcon,
  TrendingUp as TrendingIcon,
  AttachMoney as MoneyIcon,
  CheckCircle as CheckIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  EmojiEvents as TrophyIcon,
  Star as StarIcon,
  LocalFireDepartment as FireIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const DailyReport = () => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDailyReport();
  }, []);

  const fetchDailyReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getDailyReport();
      setReport(response.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch daily report');
    } finally {
      setLoading(false);
    }
  };

  const StatCard = ({ icon, title, value, subtitle, color }) => (
    <Zoom in={true} timeout={600}>
      <Card
        sx={{
          background: `linear-gradient(135deg, rgba(0, 0, 0, 0.4) 0%, ${color}20 100%)`,
          backdropFilter: 'blur(10px)',
          border: `1px solid ${color}40`,
          borderRadius: 2,
          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
          '&:hover': {
            transform: 'translateY(-5px)',
            boxShadow: `0 8px 24px ${color}40`,
            border: `1px solid ${color}60`,
          },
        }}
      >
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <Box
              sx={{
                mr: 1.5,
                color: color,
                display: 'flex',
                alignItems: 'center',
                fontSize: 32,
              }}
            >
              {icon}
            </Box>
            <Box sx={{ flex: 1 }}>
              <Typography variant="body2" sx={{ color: 'rgba(255, 255, 255, 0.7)', mb: 0.5 }}>
                {title}
              </Typography>
              <Typography variant="h4" sx={{ color: '#fff', fontWeight: 700 }}>
                {value}
              </Typography>
              {subtitle && (
                <Typography variant="caption" sx={{ color: color }}>
                  {subtitle}
                </Typography>
              )}
            </Box>
          </Box>
        </CardContent>
      </Card>
    </Zoom>
  );

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Card
          sx={{
            background: 'linear-gradient(135deg, rgba(103, 58, 183, 0.3) 0%, rgba(156, 39, 176, 0.3) 100%)',
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
          }}
        >
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
              <Slide direction="right" in={true} timeout={600}>
                <Typography
                  variant="h5"
                  sx={{
                    color: '#ce93d8',
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
                      animation: 'float 3s ease-in-out infinite',
                      '@keyframes float': {
                        '0%, 100%': { transform: 'translateY(0)' },
                        '50%': { transform: 'translateY(-10px)' },
                      },
                    }}
                  >
                    <ReportIcon />
                  </Box>
                  Daily Intelligence Report
                </Typography>
              </Slide>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Zoom in={true} timeout={800}>
                  <Tooltip title="Refresh Report">
                    <IconButton
                      onClick={fetchDailyReport}
                      disabled={loading}
                      sx={{
                        color: '#ce93d8',
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
                {report && (
                  <Zoom in={true} timeout={900}>
                    <Button
                      size="small"
                      startIcon={<DownloadIcon />}
                      sx={{
                        color: '#ce93d8',
                        borderColor: 'rgba(156, 39, 176, 0.3)',
                        '&:hover': {
                          borderColor: '#9c27b0',
                          backgroundColor: 'rgba(156, 39, 176, 0.1)',
                        },
                      }}
                    >
                      Export
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
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
                  {error}
                </Alert>
              </Collapse>
            )}

            {report && (
              <Box>
                <Fade in={true} timeout={600}>
                  <Box
                    sx={{
                      mb: 3,
                      p: 2.5,
                      background: 'linear-gradient(135deg, rgba(156, 39, 176, 0.2) 0%, rgba(103, 58, 183, 0.2) 100%)',
                      borderRadius: 2,
                      border: '1px solid rgba(156, 39, 176, 0.3)',
                      backdropFilter: 'blur(10px)',
                    }}
                  >
                    <Typography variant="h6" sx={{ color: '#ce93d8', mb: 1, fontWeight: 600 }}>
                      {report.date || new Date().toLocaleDateString('en-US', { 
                        weekday: 'long', 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric' 
                      })}
                    </Typography>
                    <Typography
                      variant="body1"
                      sx={{
                        color: 'rgba(255, 255, 255, 0.9)',
                        fontStyle: 'italic',
                        lineHeight: 1.7,
                      }}
                    >
                      {report.summary || "Boss! Aaj ka din bahut productive raha! 🔥 Dekho kya kya achieve kiya..."}
                    </Typography>
                  </Box>
                </Fade>

                <Typography
                  variant="subtitle1"
                  sx={{
                    color: '#ce93d8',
                    fontWeight: 600,
                    mb: 2,
                    textShadow: '0 0 5px rgba(156, 39, 176, 0.5)',
                  }}
                >
                  Performance Overview
                </Typography>

                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                      icon={<CheckIcon />}
                      title="Tasks Completed"
                      value={report.tasks_completed || 0}
                      subtitle={`out of ${report.total_tasks || 0}`}
                      color="#4caf50"
                    />
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                      icon={<TrendingIcon />}
                      title="Productivity"
                      value={`${report.productivity_score || 0}%`}
                      subtitle="efficiency rating"
                      color="#2196f3"
                    />
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                      icon={<MoneyIcon />}
                      title="Earnings"
                      value={`$${(report.earnings || 0).toLocaleString()}`}
                      subtitle="from bug bounties"
                      color="#ffc107"
                    />
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <StatCard
                      icon={<FireIcon />}
                      title="Streak"
                      value={`${report.streak || 0} days`}
                      subtitle="keep it up!"
                      color="#ff5722"
                    />
                  </Grid>
                </Grid>

                <Divider sx={{ my: 3, borderColor: 'rgba(156, 39, 176, 0.2)' }} />

                {report.achievements && report.achievements.length > 0 && (
                  <Box sx={{ mb: 3 }}>
                    <Typography
                      variant="subtitle1"
                      sx={{
                        color: '#ce93d8',
                        fontWeight: 600,
                        mb: 2,
                        display: 'flex',
                        alignItems: 'center',
                      }}
                    >
                      <TrophyIcon sx={{ mr: 1, color: '#ffd700' }} />
                      Today's Achievements
                    </Typography>
                    <Stack spacing={1}>
                      {report.achievements.map((achievement, index) => (
                        <Zoom key={index} in={true} timeout={400 + index * 100}>
                          <Card
                            sx={{
                              background: 'linear-gradient(135deg, rgba(255, 215, 0, 0.2) 0%, rgba(255, 193, 7, 0.2) 100%)',
                              backdropFilter: 'blur(10px)',
                              border: '1px solid rgba(255, 215, 0, 0.3)',
                              borderRadius: 2,
                              transition: 'all 0.3s ease',
                              '&:hover': {
                                transform: 'translateX(5px)',
                                boxShadow: '0 4px 20px rgba(255, 215, 0, 0.3)',
                              },
                            }}
                          >
                            <CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <StarIcon sx={{ color: '#ffd700', mr: 1.5, fontSize: 28 }} />
                                <Box sx={{ flex: 1 }}>
                                  <Typography sx={{ color: '#fff', fontWeight: 600 }}>
                                    {achievement.title}
                                  </Typography>
                                  <Typography variant="body2" sx={{ color: 'rgba(255, 255, 255, 0.7)' }}>
                                    {achievement.description}
                                  </Typography>
                                </Box>
                                <Chip
                                  label={`+${achievement.points}pts`}
                                  size="small"
                                  sx={{
                                    backgroundColor: 'rgba(255, 215, 0, 0.3)',
                                    color: '#ffd700',
                                    border: '1px solid rgba(255, 215, 0, 0.5)',
                                    fontWeight: 600,
                                  }}
                                />
                              </Box>
                            </CardContent>
                          </Card>
                        </Zoom>
                      ))}
                    </Stack>
                  </Box>
                )}

                {report.trends && (
                  <Box sx={{ mb: 3 }}>
                    <Typography
                      variant="subtitle1"
                      sx={{
                        color: '#ce93d8',
                        fontWeight: 600,
                        mb: 2,
                        display: 'flex',
                        alignItems: 'center',
                      }}
                    >
                      <TrendingIcon sx={{ mr: 1 }} />
                      Trending Opportunities
                    </Typography>
                    <Stack spacing={1}>
                      {report.trends.map((trend, index) => (
                        <Zoom key={index} in={true} timeout={400 + index * 100}>
                          <Card
                            sx={{
                              background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.3) 0%, rgba(156, 39, 176, 0.1) 100%)',
                              backdropFilter: 'blur(10px)',
                              border: '1px solid rgba(156, 39, 176, 0.3)',
                              borderRadius: 2,
                              transition: 'all 0.3s ease',
                              '&:hover': {
                                transform: 'translateX(5px)',
                                boxShadow: '0 4px 20px rgba(156, 39, 176, 0.3)',
                              },
                            }}
                          >
                            <CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}>
                              <Typography sx={{ color: '#fff', fontWeight: 600, mb: 0.5 }}>
                                {trend.title}
                              </Typography>
                              <Typography variant="body2" sx={{ color: 'rgba(255, 255, 255, 0.7)' }}>
                                {trend.description}
                              </Typography>
                            </CardContent>
                          </Card>
                        </Zoom>
                      ))}
                    </Stack>
                  </Box>
                )}

                {report.suggestions && report.suggestions.length > 0 && (
                  <Fade in={true} timeout={600}>
                    <Box
                      sx={{
                        p: 2.5,
                        background: 'linear-gradient(135deg, rgba(76, 175, 80, 0.2) 0%, rgba(139, 195, 74, 0.2) 100%)',
                        borderRadius: 2,
                        border: '1px solid rgba(76, 175, 80, 0.3)',
                        backdropFilter: 'blur(10px)',
                      }}
                    >
                      <Typography variant="subtitle2" sx={{ color: '#81c784', mb: 1.5, fontWeight: 600 }}>
                        💡 Tomorrow's Game Plan:
                      </Typography>
                      <Stack spacing={0.5}>
                        {report.suggestions.map((suggestion, index) => (
                          <Typography key={index} variant="body2" sx={{ color: 'rgba(255, 255, 255, 0.9)' }}>
                            • {suggestion}
                          </Typography>
                        ))}
                      </Stack>
                    </Box>
                  </Fade>
                )}
              </Box>
            )}

            {!report && !loading && (
              <Fade in={true} timeout={600}>
                <Box
                  sx={{
                    textAlign: 'center',
                    py: 4,
                    color: '#ce93d8',
                  }}
                >
                  <ReportIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                  <Typography variant="body1">
                    Boss! Aaj ka report generate ho raha hai... thoda wait karo! ⏰
                  </Typography>
                </Box>
              </Fade>
            )}
          </CardContent>
        </Card>
      </Box>
    </Fade>
  );
};

export default DailyReport;
