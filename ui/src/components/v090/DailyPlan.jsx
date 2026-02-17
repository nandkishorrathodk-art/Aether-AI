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
  Avatar,
} from '@mui/material';
import {
  CalendarToday as CalendarIcon,
  CheckCircle as CheckIcon,
  RadioButtonUnchecked as UncheckedIcon,
  AccessTime as TimeIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingIcon,
  EmojiEvents as TrophyIcon,
  WbSunny as MorningIcon,
  Brightness3 as EveningIcon,
  LocalCafe as BreakIcon,
  FitnessCenter as WorkoutIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const DailyPlan = () => {
  const [plan, setPlan] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDailyPlan();
  }, []);

  const fetchDailyPlan = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getDailyPlan();
      setPlan(response.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch daily plan');
    } finally {
      setLoading(false);
    }
  };

  const getTimeIcon = (time) => {
    const hour = parseInt(time.split(':')[0]);
    if (hour < 12) return <MorningIcon />;
    if (hour < 18) return <TimeIcon />;
    return <EveningIcon />;
  };

  const getTaskIcon = (type) => {
    const icons = {
      break: <BreakIcon />,
      workout: <WorkoutIcon />,
      work: <TrendingIcon />,
      default: <TimeIcon />,
    };
    return icons[type?.toLowerCase()] || icons.default;
  };

  const calculateProgress = () => {
    if (!plan?.tasks) return 0;
    const completed = plan.tasks.filter((t) => t.completed).length;
    return (completed / plan.tasks.length) * 100;
  };

  const getMotivationalMessage = () => {
    const progress = calculateProgress();
    if (progress === 0) return "Boss! Let's crush this day! 🚀";
    if (progress < 30) return "Good start boss! Keep going! 💪";
    if (progress < 70) return "Halfway there! You're doing great! 🔥";
    if (progress < 100) return "Almost done! Final push! ⚡";
    return "All done! You're a legend! 🏆";
  };

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Card
          sx={{
            background: 'linear-gradient(135deg, rgba(63, 81, 181, 0.3) 0%, rgba(3, 169, 244, 0.3) 100%)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(33, 150, 243, 0.4)',
            boxShadow: '0 0 30px rgba(33, 150, 243, 0.3), inset 0 0 20px rgba(33, 150, 243, 0.1)',
            borderRadius: 3,
            overflow: 'hidden',
            position: 'relative',
            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
            '&:hover': {
              boxShadow: '0 0 40px rgba(33, 150, 243, 0.5), inset 0 0 30px rgba(33, 150, 243, 0.15)',
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
                    color: '#90caf9',
                    display: 'flex',
                    alignItems: 'center',
                    fontWeight: 600,
                    textShadow: '0 0 10px rgba(33, 150, 243, 0.8)',
                    letterSpacing: 1,
                  }}
                >
                  <Box
                    sx={{
                      mr: 1,
                      animation: 'bounce 2s ease-in-out infinite',
                      '@keyframes bounce': {
                        '0%, 100%': { transform: 'translateY(0)' },
                        '50%': { transform: 'translateY(-5px)' },
                      },
                    }}
                  >
                    <CalendarIcon />
                  </Box>
                  Daily Plan
                </Typography>
              </Slide>
              <Zoom in={true} timeout={800}>
                <Tooltip title="Refresh Plan">
                  <IconButton
                    onClick={fetchDailyPlan}
                    disabled={loading}
                    sx={{
                      color: '#90caf9',
                      backgroundColor: 'rgba(33, 150, 243, 0.2)',
                      border: '1px solid rgba(33, 150, 243, 0.3)',
                      transition: 'all 0.3s ease',
                      '&:hover': {
                        backgroundColor: 'rgba(33, 150, 243, 0.3)',
                        transform: 'rotate(180deg)',
                        boxShadow: '0 0 15px rgba(33, 150, 243, 0.5)',
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
                    backgroundColor: 'rgba(33, 150, 243, 0.2)',
                    '& .MuiLinearProgress-bar': {
                      backgroundColor: '#2196f3',
                      boxShadow: '0 0 10px rgba(33, 150, 243, 0.8)',
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

            {plan && (
              <Box>
                <Fade in={true} timeout={600}>
                  <Box
                    sx={{
                      mb: 3,
                      p: 2.5,
                      background: 'linear-gradient(135deg, rgba(33, 150, 243, 0.2) 0%, rgba(63, 81, 181, 0.2) 100%)',
                      borderRadius: 2,
                      border: '1px solid rgba(33, 150, 243, 0.3)',
                      backdropFilter: 'blur(10px)',
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <Avatar
                        sx={{
                          bgcolor: 'rgba(33, 150, 243, 0.3)',
                          mr: 2,
                          width: 56,
                          height: 56,
                          border: '2px solid rgba(33, 150, 243, 0.5)',
                        }}
                      >
                        <TrophyIcon sx={{ fontSize: 32, color: '#ffd700' }} />
                      </Avatar>
                      <Box sx={{ flex: 1 }}>
                        <Typography
                          variant="h6"
                          sx={{
                            color: '#fff',
                            fontWeight: 600,
                            mb: 0.5,
                          }}
                        >
                          {plan.date || new Date().toLocaleDateString()}
                        </Typography>
                        <Typography
                          variant="body2"
                          sx={{
                            color: 'rgba(255, 255, 255, 0.7)',
                            fontStyle: 'italic',
                          }}
                        >
                          {getMotivationalMessage()}
                        </Typography>
                      </Box>
                    </Box>

                    <Box sx={{ mb: 1.5 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                        <Typography variant="body2" sx={{ color: '#90caf9', fontWeight: 500 }}>
                          Progress
                        </Typography>
                        <Typography variant="body2" sx={{ color: '#90caf9', fontWeight: 600 }}>
                          {Math.round(calculateProgress())}%
                        </Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={calculateProgress()}
                        sx={{
                          height: 8,
                          borderRadius: 4,
                          backgroundColor: 'rgba(33, 150, 243, 0.2)',
                          '& .MuiLinearProgress-bar': {
                            background: 'linear-gradient(90deg, #2196f3 0%, #4caf50 100%)',
                            boxShadow: '0 0 10px rgba(33, 150, 243, 0.8)',
                            borderRadius: 4,
                          },
                        }}
                      />
                    </Box>

                    {plan.goals && plan.goals.length > 0 && (
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 2 }}>
                        {plan.goals.map((goal, index) => (
                          <Zoom key={index} in={true} timeout={400 + index * 100}>
                            <Chip
                              icon={<TrophyIcon />}
                              label={goal}
                              size="small"
                              sx={{
                                backgroundColor: 'rgba(255, 215, 0, 0.2)',
                                color: '#ffd700',
                                border: '1px solid rgba(255, 215, 0, 0.3)',
                                fontWeight: 500,
                              }}
                            />
                          </Zoom>
                        ))}
                      </Box>
                    )}
                  </Box>
                </Fade>

                <Divider sx={{ my: 2, borderColor: 'rgba(33, 150, 243, 0.2)' }} />

                <Typography
                  variant="subtitle1"
                  sx={{
                    color: '#90caf9',
                    fontWeight: 600,
                    mb: 2,
                    textShadow: '0 0 5px rgba(33, 150, 243, 0.5)',
                  }}
                >
                  Today's Schedule
                </Typography>

                <Stack spacing={1.5}>
                  {plan.tasks?.map((task, index) => (
                    <Zoom key={index} in={true} timeout={400 + index * 100}>
                      <Card
                        sx={{
                          background: task.completed
                            ? 'linear-gradient(135deg, rgba(76, 175, 80, 0.2) 0%, rgba(139, 195, 74, 0.2) 100%)'
                            : 'linear-gradient(135deg, rgba(0, 0, 0, 0.3) 0%, rgba(33, 150, 243, 0.1) 100%)',
                          backdropFilter: 'blur(10px)',
                          border: task.completed
                            ? '1px solid rgba(76, 175, 80, 0.4)'
                            : '1px solid rgba(33, 150, 243, 0.3)',
                          borderRadius: 2,
                          transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                          '&:hover': {
                            transform: 'translateX(5px)',
                            boxShadow: task.completed
                              ? '0 4px 20px rgba(76, 175, 80, 0.3)'
                              : '0 4px 20px rgba(33, 150, 243, 0.3)',
                          },
                        }}
                      >
                        <CardContent sx={{ py: 1.5, px: 2, '&:last-child': { pb: 1.5 } }}>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Box
                              sx={{
                                mr: 2,
                                color: task.completed ? '#4caf50' : '#2196f3',
                                display: 'flex',
                                alignItems: 'center',
                              }}
                            >
                              {task.completed ? (
                                <CheckIcon sx={{ fontSize: 28 }} />
                              ) : (
                                <UncheckedIcon sx={{ fontSize: 28 }} />
                              )}
                            </Box>
                            <Box sx={{ flex: 1 }}>
                              <Typography
                                variant="subtitle2"
                                sx={{
                                  color: '#fff',
                                  fontWeight: 600,
                                  textDecoration: task.completed ? 'line-through' : 'none',
                                  opacity: task.completed ? 0.7 : 1,
                                }}
                              >
                                {task.title}
                              </Typography>
                              {task.description && (
                                <Typography
                                  variant="body2"
                                  sx={{
                                    color: 'rgba(255, 255, 255, 0.6)',
                                    fontSize: '0.875rem',
                                  }}
                                >
                                  {task.description}
                                </Typography>
                              )}
                            </Box>
                            {task.time && (
                              <Box
                                sx={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  gap: 0.5,
                                  color: '#90caf9',
                                  ml: 2,
                                }}
                              >
                                {getTimeIcon(task.time)}
                                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                  {task.time}
                                </Typography>
                              </Box>
                            )}
                          </Box>
                        </CardContent>
                      </Card>
                    </Zoom>
                  ))}
                </Stack>

                {(!plan.tasks || plan.tasks.length === 0) && (
                  <Fade in={true} timeout={600}>
                    <Box
                      sx={{
                        textAlign: 'center',
                        py: 4,
                        color: '#90caf9',
                      }}
                    >
                      <CalendarIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                      <Typography variant="body1">
                        Boss! Aaj ka plan abhi ready nahi hai. Main generate kar raha hoon... ⏰
                      </Typography>
                    </Box>
                  </Fade>
                )}
              </Box>
            )}
          </CardContent>
        </Card>
      </Box>
    </Fade>
  );
};

export default DailyPlan;
