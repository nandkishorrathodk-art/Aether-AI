import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
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
  ListItemText,
  ListItemIcon,
  Divider,
  Tab,
  Tabs,
  Grid,
  Paper,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  BugReport as BugIcon,
  TravelExplore as CrawlIcon,
  Security as SecurityIcon,
  Code as CodeIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Link as LinkIcon,
  Input as InputIcon,
  Visibility as VisibilityIcon,
  Shield as ShieldIcon,
  Screenshot as ScreenshotIcon,
} from '@mui/icons-material';
import api from '../../services/api';

const LiveTestingPanel = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState(0);
  
  // Crawler state
  const [crawlStats, setCrawlStats] = useState(null);
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState([]);
  const [discoveredForms, setDiscoveredForms] = useState([]);
  const [injectionPoints, setInjectionPoints] = useState([]);
  
  // Browser state
  const [browserRunning, setBrowserRunning] = useState(false);
  const [currentPage, setCurrentPage] = useState(null);
  const [pageInputs, setPageInputs] = useState([]);
  
  // Testing state
  const [selectedPayloadCategory, setSelectedPayloadCategory] = useState('xss');
  const [testResults, setTestResults] = useState([]);
  const [wafDetected, setWafDetected] = useState(null);
  
  // Settings
  const [headlessMode, setHeadlessMode] = useState(false);
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(20);

  useEffect(() => {
    const interval = setInterval(() => {
      if (isRunning) {
        fetchLiveStats();
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [isRunning]);

  const fetchLiveStats = async () => {
    try {
      const response = await api.getLiveTestingStatus();
      if (response.data) {
        setCrawlStats(response.data.crawl_stats);
        setBrowserRunning(response.data.browser_running);
        setCurrentPage(response.data.current_page);
      }
    } catch (err) {
      console.error('Failed to fetch live stats:', err);
    }
  };

  const handleStartCrawl = async () => {
    if (!targetUrl) {
      setError('Please enter a target URL');
      return;
    }

    setLoading(true);
    setError(null);
    setIsRunning(true);

    try {
      const response = await api.startLiveTesting({
        url: targetUrl,
        max_depth: maxDepth,
        max_pages: maxPages,
        headless: headlessMode,
      });

      if (response.data.status === 'success') {
        setCrawlStats(response.data.stats);
        setDiscoveredEndpoints(response.data.endpoints || []);
        setDiscoveredForms(response.data.forms || []);
        setInjectionPoints(response.data.injection_points || []);
      }
    } catch (err) {
      setError(err.message || 'Failed to start crawl');
      setIsRunning(false);
    } finally {
      setLoading(false);
    }
  };

  const handleStopTesting = async () => {
    setLoading(true);
    try {
      await api.stopLiveTesting();
      setIsRunning(false);
    } catch (err) {
      setError(err.message || 'Failed to stop testing');
    } finally {
      setLoading(false);
    }
  };

  const handleTestPayload = async (injectionPoint, payload) => {
    setLoading(true);
    try {
      const response = await api.testPayload({
        injection_point: injectionPoint,
        payload: payload,
        category: selectedPayloadCategory,
      });

      if (response.data.status === 'success') {
        const result = {
          ...response.data,
          timestamp: new Date().toISOString(),
          injectionPoint,
          payload,
        };
        setTestResults((prev) => [result, ...prev]);

        if (response.data.waf_detected) {
          setWafDetected(response.data.waf_info);
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to test payload');
    } finally {
      setLoading(false);
    }
  };

  const handleNavigateBrowser = async (url) => {
    setLoading(true);
    try {
      const response = await api.browserNavigate(url);
      if (response.data.status === 'success') {
        setCurrentPage(response.data);
        
        const inputsResponse = await api.browserGetInputs();
        if (inputsResponse.data.inputs) {
          setPageInputs(inputsResponse.data.inputs);
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to navigate');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#d32f2f',
      high: '#f57c00',
      medium: '#fbc02d',
      low: '#388e3c',
      info: '#1976d2',
    };
    return colors[severity?.toLowerCase()] || colors.info;
  };

  return (
    <Fade in={true} timeout={800}>
      <Box>
        <Box
          sx={{
            background: 'linear-gradient(135deg, rgba(255,0,0,0.1) 0%, rgba(0,0,0,0.3) 100%)',
            backdropFilter: 'blur(10px)',
            borderRadius: 2,
            p: 3,
            mb: 3,
            border: '1px solid rgba(255,0,0,0.2)',
            boxShadow: isRunning ? '0 0 20px rgba(255,0,0,0.3)' : 'none',
            transition: 'all 0.3s ease',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <SecurityIcon
              sx={{
                fontSize: 40,
                mr: 2,
                color: '#ff0000',
                animation: isRunning ? 'pulse 2s infinite' : 'none',
                '@keyframes pulse': {
                  '0%, 100%': { opacity: 1 },
                  '50%': { opacity: 0.5 },
                },
              }}
            />
            <Typography variant="h5" sx={{ fontWeight: 'bold', color: '#fff' }}>
              Live Bug Bounty Testing 🎯
            </Typography>
          </Box>

          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid item xs={12} md={8}>
              <TextField
                fullWidth
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="Enter target URL (e.g., https://example.com)"
                disabled={isRunning}
                size="small"
                sx={{
                  '& .MuiOutlinedInput-root': {
                    backgroundColor: 'rgba(0,0,0,0.3)',
                    color: '#fff',
                  },
                }}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                type="number"
                value={maxDepth}
                onChange={(e) => setMaxDepth(parseInt(e.target.value))}
                label="Max Depth"
                disabled={isRunning}
                size="small"
                sx={{
                  '& .MuiOutlinedInput-root': {
                    backgroundColor: 'rgba(0,0,0,0.3)',
                    color: '#fff',
                  },
                }}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <TextField
                fullWidth
                type="number"
                value={maxPages}
                onChange={(e) => setMaxPages(parseInt(e.target.value))}
                label="Max Pages"
                disabled={isRunning}
                size="small"
                sx={{
                  '& .MuiOutlinedInput-root': {
                    backgroundColor: 'rgba(0,0,0,0.3)',
                    color: '#fff',
                  },
                }}
              />
            </Grid>
          </Grid>

          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            {!isRunning ? (
              <Button
                variant="contained"
                startIcon={<PlayIcon />}
                onClick={handleStartCrawl}
                disabled={loading || !targetUrl}
                sx={{
                  background: 'linear-gradient(45deg, #ff0000 30%, #cc0000 90%)',
                  '&:hover': {
                    background: 'linear-gradient(45deg, #cc0000 30%, #990000 90%)',
                  },
                }}
              >
                Start Live Testing
              </Button>
            ) : (
              <Button
                variant="contained"
                startIcon={<StopIcon />}
                onClick={handleStopTesting}
                disabled={loading}
                sx={{
                  background: 'linear-gradient(45deg, #666 30%, #333 90%)',
                }}
              >
                Stop Testing
              </Button>
            )}

            <FormControlLabel
              control={
                <Switch
                  checked={headlessMode}
                  onChange={(e) => setHeadlessMode(e.target.checked)}
                  disabled={isRunning}
                />
              }
              label="Headless Mode"
              sx={{ color: '#fff' }}
            />

            <Box sx={{ flexGrow: 1 }} />

            <Chip
              icon={isRunning ? <BugIcon /> : <InfoIcon />}
              label={isRunning ? 'Testing Active' : 'Ready'}
              color={isRunning ? 'error' : 'default'}
              sx={{
                animation: isRunning ? 'pulse 2s infinite' : 'none',
              }}
            />
          </Box>

          {loading && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress
                sx={{
                  backgroundColor: 'rgba(255,255,255,0.1)',
                  '& .MuiLinearProgress-bar': {
                    background: 'linear-gradient(90deg, #ff0000, #ff6600)',
                  },
                }}
              />
            </Box>
          )}
        </Box>

        {error && (
          <Zoom in={true}>
            <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
              {error}
            </Alert>
          </Zoom>
        )}

        {wafDetected && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="subtitle2">
              <ShieldIcon sx={{ fontSize: 18, verticalAlign: 'middle', mr: 1 }} />
              WAF Detected: {wafDetected.wafs?.map(w => w.name).join(', ')}
            </Typography>
          </Alert>
        )}

        {crawlStats && (
          <Slide direction="up" in={true}>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={6} md={3}>
                <Paper
                  sx={{
                    p: 2,
                    background: 'linear-gradient(135deg, rgba(0,255,255,0.1), rgba(0,0,0,0.3))',
                    border: '1px solid rgba(0,255,255,0.3)',
                    textAlign: 'center',
                  }}
                >
                  <Typography variant="h4" sx={{ color: '#00ffff', fontWeight: 'bold' }}>
                    {crawlStats.pages_crawled || 0}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#aaa' }}>
                    Pages Crawled
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper
                  sx={{
                    p: 2,
                    background: 'linear-gradient(135deg, rgba(255,165,0,0.1), rgba(0,0,0,0.3))',
                    border: '1px solid rgba(255,165,0,0.3)',
                    textAlign: 'center',
                  }}
                >
                  <Typography variant="h4" sx={{ color: '#ffa500', fontWeight: 'bold' }}>
                    {crawlStats.endpoints_found || 0}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#aaa' }}>
                    Endpoints Found
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper
                  sx={{
                    p: 2,
                    background: 'linear-gradient(135deg, rgba(0,255,0,0.1), rgba(0,0,0,0.3))',
                    border: '1px solid rgba(0,255,0,0.3)',
                    textAlign: 'center',
                  }}
                >
                  <Typography variant="h4" sx={{ color: '#00ff00', fontWeight: 'bold' }}>
                    {crawlStats.forms_found || 0}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#aaa' }}>
                    Forms Found
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={6} md={3}>
                <Paper
                  sx={{
                    p: 2,
                    background: 'linear-gradient(135deg, rgba(255,0,255,0.1), rgba(0,0,0,0.3))',
                    border: '1px solid rgba(255,0,255,0.3)',
                    textAlign: 'center',
                  }}
                >
                  <Typography variant="h4" sx={{ color: '#ff00ff', fontWeight: 'bold' }}>
                    {crawlStats.parameters_found || 0}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#aaa' }}>
                    Parameters Found
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Slide>
        )}

        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
          <Tabs
            value={activeTab}
            onChange={(e, newValue) => setActiveTab(newValue)}
            sx={{
              '& .MuiTab-root': { color: 'rgba(255,255,255,0.6)' },
              '& .Mui-selected': { color: '#ff0000' },
              '& .MuiTabs-indicator': { backgroundColor: '#ff0000' },
            }}
          >
            <Tab icon={<LinkIcon />} label="Endpoints" />
            <Tab icon={<InputIcon />} label="Injection Points" />
            <Tab icon={<BugIcon />} label="Test Results" />
            <Tab icon={<VisibilityIcon />} label="Live Browser" />
          </Tabs>
        </Box>

        {activeTab === 0 && (
          <Card sx={{ background: 'rgba(0,20,20,0.5)', backdropFilter: 'blur(10px)' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: '#00ffff' }}>
                Discovered Endpoints ({discoveredEndpoints.length})
              </Typography>
              <List>
                {discoveredEndpoints.slice(0, 20).map((endpoint, index) => (
                  <Fade in={true} key={index} timeout={300 * (index + 1)}>
                    <ListItem>
                      <ListItemIcon>
                        <LinkIcon sx={{ color: '#00ffff' }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={endpoint.url}
                        secondary={`${endpoint.method} | ${endpoint.status_code} | Depth: ${endpoint.depth}`}
                        primaryTypographyProps={{ sx: { color: '#fff', fontSize: 14 } }}
                        secondaryTypographyProps={{ sx: { color: '#aaa', fontSize: 12 } }}
                      />
                      <Chip
                        label={endpoint.status_code}
                        size="small"
                        color={endpoint.status_code === 200 ? 'success' : 'warning'}
                      />
                    </ListItem>
                  </Fade>
                ))}
              </List>
            </CardContent>
          </Card>
        )}

        {activeTab === 1 && (
          <Card sx={{ background: 'rgba(0,20,20,0.5)', backdropFilter: 'blur(10px)' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: '#00ffff' }}>
                Injection Points ({injectionPoints.length})
              </Typography>
              <List>
                {injectionPoints.slice(0, 20).map((point, index) => (
                  <Fade in={true} key={index} timeout={300 * (index + 1)}>
                    <ListItem>
                      <ListItemIcon>
                        <InputIcon sx={{ color: '#ffa500' }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={`${point.type}: ${point.parameter || point.input_name}`}
                        secondary={`${point.method} ${point.url}`}
                        primaryTypographyProps={{ sx: { color: '#fff', fontSize: 14 } }}
                        secondaryTypographyProps={{ sx: { color: '#aaa', fontSize: 12 } }}
                      />
                      <Button
                        size="small"
                        startIcon={<BugIcon />}
                        onClick={() => handleTestPayload(point, `<script>alert('XSS')</script>`)}
                        sx={{ color: '#ff0000' }}
                      >
                        Test
                      </Button>
                    </ListItem>
                  </Fade>
                ))}
              </List>
            </CardContent>
          </Card>
        )}

        {activeTab === 2 && (
          <Card sx={{ background: 'rgba(0,20,20,0.5)', backdropFilter: 'blur(10px)' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: '#00ffff' }}>
                Test Results ({testResults.length})
              </Typography>
              <List>
                {testResults.map((result, index) => (
                  <Fade in={true} key={index} timeout={300}>
                    <Box sx={{ mb: 2 }}>
                      <Paper
                        sx={{
                          p: 2,
                          background: result.vulnerable
                            ? 'linear-gradient(135deg, rgba(255,0,0,0.2), rgba(0,0,0,0.3))'
                            : 'linear-gradient(135deg, rgba(0,255,0,0.1), rgba(0,0,0,0.3))',
                          border: result.vulnerable ? '1px solid #ff0000' : '1px solid #00ff00',
                        }}
                      >
                        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                          {result.vulnerable ? (
                            <ErrorIcon sx={{ color: '#ff0000', mr: 1 }} />
                          ) : (
                            <CheckIcon sx={{ color: '#00ff00', mr: 1 }} />
                          )}
                          <Typography variant="subtitle1" sx={{ color: '#fff', fontWeight: 'bold' }}>
                            {result.vulnerable ? 'Vulnerable!' : 'Not Vulnerable'}
                          </Typography>
                          <Box sx={{ flexGrow: 1 }} />
                          <Chip
                            label={result.injectionPoint?.type}
                            size="small"
                            sx={{ backgroundColor: 'rgba(255,255,255,0.1)' }}
                          />
                        </Box>
                        <Typography variant="body2" sx={{ color: '#aaa', mb: 1 }}>
                          Payload: <code style={{ color: '#ff6600' }}>{result.payload}</code>
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#888' }}>
                          {new Date(result.timestamp).toLocaleString()}
                        </Typography>
                      </Paper>
                    </Box>
                  </Fade>
                ))}
              </List>
            </CardContent>
          </Card>
        )}

        {activeTab === 3 && (
          <Card sx={{ background: 'rgba(0,20,20,0.5)', backdropFilter: 'blur(10px)' }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, color: '#00ffff' }}>
                Live Browser View
              </Typography>
              {currentPage && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" sx={{ color: '#fff' }}>
                    Current URL: {currentPage.url}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#aaa' }}>
                    Title: {currentPage.title}
                  </Typography>
                </Box>
              )}
              <Typography variant="subtitle2" sx={{ color: '#fff', mb: 1 }}>
                Input Fields ({pageInputs.length})
              </Typography>
              <List>
                {pageInputs.map((input, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <InputIcon sx={{ color: '#ffa500' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={`${input.name || input.id || 'unnamed'} (${input.type})`}
                      secondary={input.placeholder}
                      primaryTypographyProps={{ sx: { color: '#fff', fontSize: 14 } }}
                      secondaryTypographyProps={{ sx: { color: '#aaa', fontSize: 12 } }}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        )}
      </Box>
    </Fade>
  );
};

export default LiveTestingPanel;
