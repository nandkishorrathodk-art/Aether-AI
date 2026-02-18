import axios from 'axios';
import io from 'socket.io-client';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const WS_URL = process.env.REACT_APP_WS_URL || 'http://localhost:8000';

const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.code === 'ECONNABORTED' || error.message.includes('timeout')) {
      console.error('Request timeout:', originalRequest.url);
      throw new Error('Request timed out. Please try again.');
    }

    if (error.response?.status >= 500 && !originalRequest._retry) {
      originalRequest._retry = true;
      await new Promise(resolve => setTimeout(resolve, 1000));
      return axiosInstance(originalRequest);
    }

    throw error;
  }
);

class APIClient {
  constructor() {
    this.socket = null;
  }

  async chat(message, sessionId = null, provider = null) {
    try {
      const response = await axiosInstance.post('/api/v1/chat', {
        message,
        session_id: sessionId,
        provider,
      });
      return response.data;
    } catch (error) {
      console.error('Chat error:', error);
      throw this._handleError(error);
    }
  }

  async conversation(message, sessionId, useContext = true) {
    try {
      const response = await axiosInstance.post('/api/v1/chat/conversation', {
        message,
        session_id: sessionId,
        use_context: useContext,
      });
      return response.data;
    } catch (error) {
      console.error('Conversation error:', error);
      throw this._handleError(error);
    }
  }

  async getConversationHistory(sessionId, limit = 20) {
    try {
      const response = await axiosInstance.get(
        `/api/v1/chat/conversation/history/${sessionId}`,
        { params: { limit } }
      );
      return response.data;
    } catch (error) {
      console.error('Get history error:', error);
      throw this._handleError(error);
    }
  }

  async clearSession(sessionId) {
    try {
      await axiosInstance.delete(`/api/v1/chat/conversation/session/${sessionId}`);
      return true;
    } catch (error) {
      console.error('Clear session error:', error);
      throw this._handleError(error);
    }
  }

  async getProviders() {
    try {
      const response = await axiosInstance.get('/api/v1/chat/providers');
      return response.data;
    } catch (error) {
      console.error('Get providers error:', error);
      throw this._handleError(error);
    }
  }

  async getCostStats() {
    try {
      const response = await axiosInstance.get('/api/v1/chat/cost-stats');
      return response.data;
    } catch (error) {
      console.error('Get cost stats error:', error);
      throw this._handleError(error);
    }
  }

  async transcribeAudio(audioBlob) {
    try {
      const formData = new FormData();
      formData.append('file', audioBlob, 'audio.wav');

      const response = await axiosInstance.post('/api/v1/voice/transcribe', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return response.data;
    } catch (error) {
      console.error('Transcribe error:', error);
      throw this._handleError(error);
    }
  }

  async synthesizeSpeech(text, voice = 'default') {
    try {
      const response = await axiosInstance.post('/api/v1/voice/speak', {
        text,
        voice,
      });
      return response.data;
    } catch (error) {
      console.error('Synthesize error:', error);
      throw this._handleError(error);
    }
  }

  async getAudioDevices() {
    try {
      const response = await axiosInstance.get('/api/v1/voice/devices');
      return response.data;
    } catch (error) {
      console.error('Get devices error:', error);
      throw this._handleError(error);
    }
  }

  async getSettings() {
    try {
      const response = await axiosInstance.get('/api/v1/settings/');
      return response.data;
    } catch (error) {
      console.error('Get settings error:', error);
      throw this._handleError(error);
    }
  }

  async updateSettings(settings) {
    try {
      const response = await axiosInstance.put('/api/v1/settings/', settings);
      return response.data;
    } catch (error) {
      console.error('Update settings error:', error);
      throw this._handleError(error);
    }
  }

  async rememberMemory(content, memoryType = 'user', metadata = {}) {
    try {
      const response = await axiosInstance.post('/api/v1/memory/remember', {
        content,
        memory_type: memoryType,
        metadata,
      });
      return response.data;
    } catch (error) {
      console.error('Remember error:', error);
      throw this._handleError(error);
    }
  }

  async recallMemory(query, memoryType = null, limit = 5) {
    try {
      const response = await axiosInstance.post('/api/v1/memory/recall', {
        query,
        memory_type: memoryType,
        limit,
      });
      return response.data;
    } catch (error) {
      console.error('Recall error:', error);
      throw this._handleError(error);
    }
  }

  connectWebSocket(callbacks = {}) {
    if (this.socket?.connected) {
      return this.socket;
    }

    this.socket = io(WS_URL, {
      transports: ['websocket'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
    });

    this.socket.on('connect', () => {
      console.log('WebSocket connected');
      callbacks.onConnect?.();
    });

    this.socket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      callbacks.onDisconnect?.();
    });

    this.socket.on('error', (error) => {
      console.error('WebSocket error:', error);
      callbacks.onError?.(error);
    });

    this.socket.on('message', (data) => {
      callbacks.onMessage?.(data);
    });

    this.socket.on('notification', (data) => {
      callbacks.onNotification?.(data);
    });

    return this.socket;
  }

  disconnectWebSocket() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  async getMonitoringStatus() {
    try {
      const response = await axiosInstance.get('/api/v1/monitor/status');
      return response.data;
    } catch (error) {
      console.error('Get monitoring status error:', error);
      throw this._handleError(error);
    }
  }

  async startMonitoring() {
    try {
      const response = await axiosInstance.post('/api/v1/monitor/start');
      return response.data;
    } catch (error) {
      console.error('Start monitoring error:', error);
      throw this._handleError(error);
    }
  }

  async stopMonitoring() {
    try {
      const response = await axiosInstance.post('/api/v1/monitor/stop');
      return response.data;
    } catch (error) {
      console.error('Stop monitoring error:', error);
      throw this._handleError(error);
    }
  }

  async getCurrentContext() {
    try {
      const response = await axiosInstance.get('/api/v1/monitor/current-context');
      return response.data;
    } catch (error) {
      console.error('Get current context error:', error);
      throw this._handleError(error);
    }
  }

  async takeScreenshot() {
    try {
      const response = await axiosInstance.get('/api/v1/monitor/screenshot');
      return response.data;
    } catch (error) {
      console.error('Take screenshot error:', error);
      throw this._handleError(error);
    }
  }

  async getProactiveSuggestions() {
    try {
      const response = await axiosInstance.get('/api/v1/proactive/suggestions');
      return response.data;
    } catch (error) {
      console.error('Get proactive suggestions error:', error);
      throw this._handleError(error);
    }
  }

  async executeProactiveSuggestion(suggestionId) {
    try {
      const response = await axiosInstance.post('/api/v1/proactive/execute-suggestion', {
        suggestion_id: suggestionId,
      });
      return response.data;
    } catch (error) {
      console.error('Execute proactive suggestion error:', error);
      throw this._handleError(error);
    }
  }

  async getDailyPlan() {
    try {
      const response = await axiosInstance.get('/api/v1/proactive/daily-plan');
      return response.data;
    } catch (error) {
      console.error('Get daily plan error:', error);
      throw this._handleError(error);
    }
  }

  async getControlPermissions() {
    try {
      const response = await axiosInstance.get('/api/v1/control/permissions');
      return response.data;
    } catch (error) {
      console.error('Get control permissions error:', error);
      throw this._handleError(error);
    }
  }

  async controlMouseClick(x, y) {
    try {
      const response = await axiosInstance.post('/api/v1/control/mouse/click', { x, y });
      return response.data;
    } catch (error) {
      console.error('Control mouse click error:', error);
      throw this._handleError(error);
    }
  }

  async controlKeyboardType(text) {
    try {
      const response = await axiosInstance.post('/api/v1/control/keyboard/type', { text });
      return response.data;
    } catch (error) {
      console.error('Control keyboard type error:', error);
      throw this._handleError(error);
    }
  }

  async controlLaunchApp(appName) {
    try {
      const response = await axiosInstance.post('/api/v1/control/app/launch', {
        app_name: appName,
      });
      return response.data;
    } catch (error) {
      console.error('Control launch app error:', error);
      throw this._handleError(error);
    }
  }

  async getBugBountyStatus() {
    try {
      const response = await axiosInstance.get('/api/v1/bugbounty/auto/status');
      return response.data;
    } catch (error) {
      console.error('Get bug bounty status error:', error);
      throw this._handleError(error);
    }
  }

  async startBugBountyScan() {
    try {
      const response = await axiosInstance.post('/api/v1/bugbounty/auto/start');
      return response.data;
    } catch (error) {
      console.error('Start bug bounty scan error:', error);
      throw this._handleError(error);
    }
  }

  async stopBugBountyScan() {
    try {
      const response = await axiosInstance.post('/api/v1/bugbounty/auto/stop');
      return response.data;
    } catch (error) {
      console.error('Stop bug bounty scan error:', error);
      throw this._handleError(error);
    }
  }

  async generateBugBountyReport() {
    try {
      const response = await axiosInstance.post('/api/v1/bugbounty/auto/generate-report');
      return response.data;
    } catch (error) {
      console.error('Generate bug bounty report error:', error);
      throw this._handleError(error);
    }
  }

  async getDailyReport() {
    try {
      const response = await axiosInstance.get('/api/v1/intelligence/daily-report');
      return response.data;
    } catch (error) {
      console.error('Get daily report error:', error);
      throw this._handleError(error);
    }
  }

  async getTrends() {
    try {
      const response = await axiosInstance.get('/api/v1/intelligence/trends');
      return response.data;
    } catch (error) {
      console.error('Get trends error:', error);
      throw this._handleError(error);
    }
  }

  async getPersonalitySettings() {
    try {
      const response = await axiosInstance.get('/api/v1/personality/settings');
      return response.data;
    } catch (error) {
      console.error('Get personality settings error:', error);
      throw this._handleError(error);
    }
  }

  async updatePersonalitySettings(settings) {
    try {
      const response = await axiosInstance.put('/api/v1/personality/settings', settings);
      return response.data;
    } catch (error) {
      console.error('Update personality settings error:', error);
      throw this._handleError(error);
    }
  }

  async startLiveTesting(config) {
    try {
      const response = await axiosInstance.post('/api/v1/live-testing/start', config);
      return response.data;
    } catch (error) {
      console.error('Start live testing error:', error);
      throw this._handleError(error);
    }
  }

  async stopLiveTesting() {
    try {
      const response = await axiosInstance.post('/api/v1/live-testing/stop');
      return response.data;
    } catch (error) {
      console.error('Stop live testing error:', error);
      throw this._handleError(error);
    }
  }

  async getLiveTestingStatus() {
    try {
      const response = await axiosInstance.get('/api/v1/live-testing/status');
      return response.data;
    } catch (error) {
      console.error('Get live testing status error:', error);
      throw this._handleError(error);
    }
  }

  async testPayload(data) {
    try {
      const response = await axiosInstance.post('/api/v1/live-testing/test-payload', data);
      return response.data;
    } catch (error) {
      console.error('Test payload error:', error);
      throw this._handleError(error);
    }
  }

  async browserNavigate(url) {
    try {
      const response = await axiosInstance.post('/api/v1/live-testing/browser/navigate', { url });
      return response.data;
    } catch (error) {
      console.error('Browser navigate error:', error);
      throw this._handleError(error);
    }
  }

  async browserGetInputs() {
    try {
      const response = await axiosInstance.get('/api/v1/live-testing/browser/inputs');
      return response.data;
    } catch (error) {
      console.error('Browser get inputs error:', error);
      throw this._handleError(error);
    }
  }

  async browserScreenshot() {
    try {
      const response = await axiosInstance.post('/api/v1/live-testing/browser/screenshot');
      return response.data;
    } catch (error) {
      console.error('Browser screenshot error:', error);
      throw this._handleError(error);
    }
  }

  async getPayloads(category, maxPayloads = 20) {
    try {
      const response = await axiosInstance.get(`/api/v1/live-testing/payloads/${category}`, {
        params: { max_payloads: maxPayloads }
      });
      return response.data;
    } catch (error) {
      console.error('Get payloads error:', error);
      throw this._handleError(error);
    }
  }

  async detectWaf() {
    try {
      const response = await axiosInstance.post('/api/v1/live-testing/detect-waf');
      return response.data;
    } catch (error) {
      console.error('Detect WAF error:', error);
      throw this._handleError(error);
    }
  }

  _handleError(error) {
    if (error.response) {
      const { status, data } = error.response;
      if (status === 400) {
        return new Error(data.detail || 'Invalid request');
      } else if (status === 404) {
        return new Error('Resource not found');
      } else if (status === 429) {
        return new Error('Too many requests. Please wait a moment.');
      } else if (status >= 500) {
        return new Error('Server error. Please try again later.');
      }
    } else if (error.request) {
      return new Error('Unable to connect to server. Check if backend is running.');
    }
    return error;
  }
}

export default new APIClient();
