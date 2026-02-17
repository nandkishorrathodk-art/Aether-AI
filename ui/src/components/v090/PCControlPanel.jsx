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
  TextField,
  Alert,
  Fade,
  Zoom,
  Slide,
  Collapse,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Mouse as MouseIcon,
  Keyboard as KeyboardIcon,
  Apps as AppsIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon,
  PlayArrow as PlayIcon,
  Refresh as RefreshIcon,
  Lock as LockIcon,
  LockOpen as UnlockIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const PCControlPanel = () => {
  const [permissions, setPermissions] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [confirmDialog, setConfirmDialog] = useState({ open: false, action: null });
  const [actionInput, setActionInput] = useState({ type: '', data: '' });

  useEffect(() => {
    fetchPermissions();
  }, []);

  const fetchPermissions = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.getControlPermissions();
      setPermissions(response.data);
    } catch (err) {
      setError(err.message || 'Failed to fetch permissions');
    } finally {
      setLoading(false);
    }
  };

  const handleMouseClick = async (x, y) => {
    const action = { type: 'mouse_click', x, y };
    setConfirmDialog({ open: true, action });
  };

  const handleKeyboardType = async (text) => {
    const action = { type: 'keyboard_type', text };
    setConfirmDialog({ open: true, action });
  };

  const handleLaunchApp = async (appName) => {
    const action = { type: 'launch_app', app: appName };
    setConfirmDialog({ open: true, action });
  };

  const executeAction = async () => {
    setLoading(true);
    setError(null);
    try {
      const { action } = confirmDialog;
      let response;
      
      switch (action.type) {
        case 'mouse_click':
          response = await api.controlMouseClick(action.x, action.y);
          break;
        case 'keyboard_type':
          response = await api.controlKeyboardType(action.text);
          break;
        case 'launch_app':
          response = await api.controlLaunchApp(action.app);
          break;
        default:
          throw new Error('Unknown action type');
      }
      
      setConfirmDialog({ open: false, action: null });
      setActionInput({ type: '', data: '' });
    } catch (err) {
      setError(err.message || 'Failed to execute action');
    } finally {
      setLoading(false);
    }
  };

  const quickActions = [
    { name: 'Notepad', icon: <AppsIcon />, color: '#4caf50' },
    { name: 'Burp Suite', icon: <SecurityIcon />, color: '#ff5722' },
    { name: 'Chrome', icon: <AppsIcon />, color: '#2196f3' },
    { name: 'VS Code', icon: <AppsIcon />, color: '#00bcd4' },
  ];

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Card
          sx={{
            background: 'linear-gradient(135deg, rgba(255, 87, 34, 0.3) 0%, rgba(244, 67, 54, 0.3) 100%)',
            backdropFilter: 'blur(20px)',
            border: '1px solid rgba(255, 87, 34, 0.4)',
            boxShadow: '0 0 30px rgba(255, 87, 34, 0.3), inset 0 0 20px rgba(255, 87, 34, 0.1)',
            borderRadius: 3,
            overflow: 'hidden',
            position: 'relative',
            transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
            '&:hover': {
              boxShadow: '0 0 40px rgba(255, 87, 34, 0.5), inset 0 0 30px rgba(255, 87, 34, 0.15)',
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
                    color: '#ffab91',
                    display: 'flex',
                    alignItems: 'center',
                    fontWeight: 600,
                    textShadow: '0 0 10px rgba(255, 87, 34, 0.8)',
                    letterSpacing: 1,
                  }}
                >
                  <Box
                    sx={{
                      mr: 1,
                      animation: 'shake 3s ease-in-out infinite',
                      '@keyframes shake': {
                        '0%, 100%': { transform: 'rotate(0deg)' },
                        '25%': { transform: 'rotate(-5deg)' },
                        '75%': { transform: 'rotate(5deg)' },
                      },
                    }}
                  >
                    <ComputerIcon />
                  </Box>
                  PC Control Hub
                </Typography>
              </Slide>
              <Zoom in={true} timeout={800}>
                <Tooltip title="Refresh Permissions">
                  <IconButton
                    onClick={fetchPermissions}
                    disabled={loading}
                    sx={{
                      color: '#ffab91',
                      backgroundColor: 'rgba(255, 87, 34, 0.2)',
                      border: '1px solid rgba(255, 87, 34, 0.3)',
                      transition: 'all 0.3s ease',
                      '&:hover': {
                        backgroundColor: 'rgba(255, 87, 34, 0.3)',
                        transform: 'rotate(180deg)',
                        boxShadow: '0 0 15px rgba(255, 87, 34, 0.5)',
                      },
                    }}
                  >
                    <RefreshIcon />
                  </IconButton>
                </Tooltip>
              </Zoom>
            </Box>

            {error && (
              <Collapse in={Boolean(error)}>
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
                  {error}
                </Alert>
              </Collapse>
            )}

            <Fade in={true} timeout={600}>
              <Alert
                severity="warning"
                icon={<WarningIcon />}
                sx={{
                  mb: 3,
                  backgroundColor: 'rgba(255, 152, 0, 0.1)',
                  border: '1px solid rgba(255, 152, 0, 0.3)',
                  color: '#ffb74d',
                }}
              >
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  ⚠️ Safety Mode ON - All actions require confirmation
                </Typography>
              </Alert>
            </Fade>

            {permissions && (
              <Box sx={{ mb: 3 }}>
                <Typography
                  variant="subtitle1"
                  sx={{
                    color: '#ffab91',
                    fontWeight: 600,
                    mb: 2,
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  <SecurityIcon sx={{ mr: 1 }} />
                  Active Permissions
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" gap={1}>
                  {permissions.mouse_control && (
                    <Zoom in={true} timeout={400}>
                      <Chip
                        icon={<MouseIcon />}
                        label="Mouse Control"
                        sx={{
                          backgroundColor: 'rgba(76, 175, 80, 0.2)',
                          color: '#81c784',
                          border: '1px solid rgba(76, 175, 80, 0.3)',
                        }}
                      />
                    </Zoom>
                  )}
                  {permissions.keyboard_control && (
                    <Zoom in={true} timeout={500}>
                      <Chip
                        icon={<KeyboardIcon />}
                        label="Keyboard Control"
                        sx={{
                          backgroundColor: 'rgba(76, 175, 80, 0.2)',
                          color: '#81c784',
                          border: '1px solid rgba(76, 175, 80, 0.3)',
                        }}
                      />
                    </Zoom>
                  )}
                  {permissions.app_control && (
                    <Zoom in={true} timeout={600}>
                      <Chip
                        icon={<AppsIcon />}
                        label="App Control"
                        sx={{
                          backgroundColor: 'rgba(76, 175, 80, 0.2)',
                          color: '#81c784',
                          border: '1px solid rgba(76, 175, 80, 0.3)',
                        }}
                      />
                    </Zoom>
                  )}
                </Stack>
              </Box>
            )}

            <Typography
              variant="subtitle1"
              sx={{
                color: '#ffab91',
                fontWeight: 600,
                mb: 2,
              }}
            >
              Quick Actions
            </Typography>

            <Stack spacing={2}>
              <Zoom in={true} timeout={600}>
                <Card
                  sx={{
                    background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.3) 0%, rgba(255, 87, 34, 0.1) 100%)',
                    backdropFilter: 'blur(10px)',
                    border: '1px solid rgba(255, 87, 34, 0.2)',
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <MouseIcon sx={{ mr: 1, color: '#ffab91' }} />
                      <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 600 }}>
                        Mouse Control
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <TextField
                        size="small"
                        placeholder="X"
                        type="number"
                        value={actionInput.type === 'mouse' ? actionInput.data.split(',')[0] : ''}
                        onChange={(e) =>
                          setActionInput({
                            type: 'mouse',
                            data: `${e.target.value},${actionInput.data.split(',')[1] || ''}`,
                          })
                        }
                        sx={{
                          flex: 1,
                          '& .MuiOutlinedInput-root': {
                            color: '#fff',
                            '& fieldset': { borderColor: 'rgba(255, 87, 34, 0.3)' },
                          },
                        }}
                      />
                      <TextField
                        size="small"
                        placeholder="Y"
                        type="number"
                        value={actionInput.type === 'mouse' ? actionInput.data.split(',')[1] : ''}
                        onChange={(e) =>
                          setActionInput({
                            type: 'mouse',
                            data: `${actionInput.data.split(',')[0] || ''},${e.target.value}`,
                          })
                        }
                        sx={{
                          flex: 1,
                          '& .MuiOutlinedInput-root': {
                            color: '#fff',
                            '& fieldset': { borderColor: 'rgba(255, 87, 34, 0.3)' },
                          },
                        }}
                      />
                      <Button
                        variant="contained"
                        onClick={() => {
                          const [x, y] = actionInput.data.split(',');
                          handleMouseClick(parseInt(x), parseInt(y));
                        }}
                        disabled={!actionInput.data || actionInput.type !== 'mouse'}
                        sx={{
                          background: 'linear-gradient(135deg, #ff5722 0%, #f44336 100%)',
                          '&:hover': {
                            background: 'linear-gradient(135deg, #f44336 0%, #e91e63 100%)',
                          },
                        }}
                      >
                        Click
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Zoom>

              <Zoom in={true} timeout={700}>
                <Card
                  sx={{
                    background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.3) 0%, rgba(255, 87, 34, 0.1) 100%)',
                    backdropFilter: 'blur(10px)',
                    border: '1px solid rgba(255, 87, 34, 0.2)',
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <KeyboardIcon sx={{ mr: 1, color: '#ffab91' }} />
                      <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 600 }}>
                        Keyboard Control
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <TextField
                        size="small"
                        placeholder="Type text here..."
                        fullWidth
                        value={actionInput.type === 'keyboard' ? actionInput.data : ''}
                        onChange={(e) => setActionInput({ type: 'keyboard', data: e.target.value })}
                        sx={{
                          '& .MuiOutlinedInput-root': {
                            color: '#fff',
                            '& fieldset': { borderColor: 'rgba(255, 87, 34, 0.3)' },
                          },
                        }}
                      />
                      <Button
                        variant="contained"
                        onClick={() => handleKeyboardType(actionInput.data)}
                        disabled={!actionInput.data || actionInput.type !== 'keyboard'}
                        sx={{
                          background: 'linear-gradient(135deg, #ff5722 0%, #f44336 100%)',
                          '&:hover': {
                            background: 'linear-gradient(135deg, #f44336 0%, #e91e63 100%)',
                          },
                        }}
                      >
                        Type
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Zoom>

              <Zoom in={true} timeout={800}>
                <Card
                  sx={{
                    background: 'linear-gradient(135deg, rgba(0, 0, 0, 0.3) 0%, rgba(255, 87, 34, 0.1) 100%)',
                    backdropFilter: 'blur(10px)',
                    border: '1px solid rgba(255, 87, 34, 0.2)',
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                      <AppsIcon sx={{ mr: 1, color: '#ffab91' }} />
                      <Typography variant="subtitle2" sx={{ color: '#fff', fontWeight: 600 }}>
                        Launch Applications
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {quickActions.map((app, index) => (
                        <Button
                          key={index}
                          variant="outlined"
                          startIcon={app.icon}
                          onClick={() => handleLaunchApp(app.name)}
                          sx={{
                            color: app.color,
                            borderColor: `${app.color}40`,
                            backgroundColor: `${app.color}10`,
                            transition: 'all 0.3s ease',
                            '&:hover': {
                              borderColor: app.color,
                              backgroundColor: `${app.color}20`,
                              transform: 'translateY(-2px)',
                              boxShadow: `0 4px 12px ${app.color}40`,
                            },
                          }}
                        >
                          {app.name}
                        </Button>
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Zoom>
            </Stack>
          </CardContent>
        </Card>

        <Dialog
          open={confirmDialog.open}
          onClose={() => setConfirmDialog({ open: false, action: null })}
          PaperProps={{
            sx: {
              backgroundColor: 'rgba(0, 20, 20, 0.95)',
              backdropFilter: 'blur(20px)',
              border: '1px solid rgba(255, 87, 34, 0.4)',
              borderRadius: 2,
            },
          }}
        >
          <DialogTitle sx={{ color: '#ffab91' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <WarningIcon sx={{ mr: 1 }} />
              Confirm Action
            </Box>
          </DialogTitle>
          <DialogContent>
            <Typography sx={{ color: '#fff' }}>
              Boss, sure karna chahte ho yeh action?
            </Typography>
            {confirmDialog.action && (
              <Box
                sx={{
                  mt: 2,
                  p: 2,
                  backgroundColor: 'rgba(255, 87, 34, 0.1)',
                  borderRadius: 1,
                  border: '1px solid rgba(255, 87, 34, 0.3)',
                }}
              >
                <Typography variant="body2" sx={{ color: '#ffab91', fontFamily: 'monospace' }}>
                  {JSON.stringify(confirmDialog.action, null, 2)}
                </Typography>
              </Box>
            )}
          </DialogContent>
          <DialogActions>
            <Button
              onClick={() => setConfirmDialog({ open: false, action: null })}
              sx={{ color: '#fff' }}
            >
              Cancel
            </Button>
            <Button
              onClick={executeAction}
              variant="contained"
              disabled={loading}
              sx={{
                background: 'linear-gradient(135deg, #ff5722 0%, #f44336 100%)',
              }}
            >
              Confirm
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    </Fade>
  );
};

export default PCControlPanel;
