/**
 * Voice Service - TTS and STT API calls
 */

const API_BASE = 'http://localhost:8000/api/v1';

class VoiceService {
  /**
   * Text-to-Speech
   */
  async speak(text, options = {}) {
    const {
      voice = 'male',
      speed = 1.0,
      play = true,
      provider = 'local'
    } = options;

    try {
      const response = await fetch(`${API_BASE}/voice/speak`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          voice,
          speed,
          play,
          provider
        })
      });

      if (!response.ok) {
        throw new Error(`TTS failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('TTS Error:', error);
      throw error;
    }
  }

  /**
   * Speech-to-Text (file upload)
   */
  async transcribe(audioBlob, options = {}) {
    const {
      language = 'en',
      model = 'base'
    } = options;

    const formData = new FormData();
    formData.append('file', audioBlob, 'audio.wav');
    formData.append('language', language);
    formData.append('model', model);

    try {
      const response = await fetch(`${API_BASE}/voice/transcribe`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`STT failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('STT Error:', error);
      throw error;
    }
  }

  /**
   * Real-time transcription
   */
  async transcribeRealtime(duration = 5) {
    try {
      const response = await fetch(`${API_BASE}/voice/transcribe-realtime`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ duration })
      });

      if (!response.ok) {
        throw new Error(`Real-time STT failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Real-time STT Error:', error);
      throw error;
    }
  }

  /**
   * Get available voices
   */
  async getVoices() {
    try {
      const response = await fetch(`${API_BASE}/voice/tts/voices`);
      
      if (!response.ok) {
        throw new Error(`Failed to get voices: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Get Voices Error:', error);
      return { voices: [] };
    }
  }

  /**
   * Get available audio devices
   */
  async getDevices() {
    try {
      const response = await fetch(`${API_BASE}/voice/devices`);
      
      if (!response.ok) {
        throw new Error(`Failed to get devices: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Get Devices Error:', error);
      return { devices: [] };
    }
  }

  /**
   * Wake word status
   */
  async getWakeWordStatus() {
    try {
      const response = await fetch(`${API_BASE}/voice/wake-word/status`);
      
      if (!response.ok) {
        throw new Error(`Failed to get wake word status: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Wake Word Status Error:', error);
      return { is_listening: false };
    }
  }

  /**
   * Start wake word detection
   */
  async startWakeWord() {
    try {
      const response = await fetch(`${API_BASE}/voice/wake-word/start`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to start wake word: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Start Wake Word Error:', error);
      throw error;
    }
  }

  /**
   * Stop wake word detection
   */
  async stopWakeWord() {
    try {
      const response = await fetch(`${API_BASE}/voice/wake-word/stop`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        throw new Error(`Failed to stop wake word: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Stop Wake Word Error:', error);
      throw error;
    }
  }
}

export default new VoiceService();
