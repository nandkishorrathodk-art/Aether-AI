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
