/**
 * Voice Service - TTS and STT API calls
 */

const API_BASE = 'http://localhost:8000/api/v1';

class VoiceService {
  constructor() {
    this.currentAudio = null;
  }

  /**
   * Text-to-Speech (Downloads audio and plays in browser/Electron)
   */
  async speak(text, options = {}) {
    const {
      voice = 'female',
      speed = 1.0,
      play = true
    } = options;

    try {
      console.log('[VOICE] speak() called with text:', text);
      
      // Call /synthesize to get audio file
      console.log('[VOICE] Fetching audio from backend...');
      const response = await fetch(`${API_BASE}/voice/synthesize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text,
          voice,
          rate: Math.round(speed * 160), // Convert speed to rate
          use_cache: true
        })
      });

      console.log('[VOICE] Fetch response received, status:', response.status);

      if (!response.ok) {
        throw new Error(`TTS failed: ${response.statusText}`);
      }

      const audioBlob = await response.blob();
      console.log('[VOICE] Audio blob received, size:', audioBlob.size);

      if (play) {
        console.log('[VOICE] Starting audio playback...');
        // Play audio in browser/Electron
        await this.playAudioBlob(audioBlob);
        console.log('[VOICE] Audio playback completed');
      }

      return { 
        status: 'success', 
        text,
        audio_size_bytes: audioBlob.size 
      };
    } catch (error) {
      console.error('[VOICE] TTS Error:', error);
      throw error;
    }
  }

  /**
   * Play audio blob using HTML5 Audio API
   */
  async playAudioBlob(blob) {
    if (this.currentAudio) {
      console.log('[VOICE] Stopping previous audio...');
      this.currentAudio.pause();
      this.currentAudio.currentTime = 0;
      this.currentAudio = null;
    }

    return new Promise((resolve, reject) => {
      console.log('[VOICE] Creating new Audio element for playback');
      const audio = new Audio();
      const url = URL.createObjectURL(blob);
      
      this.currentAudio = audio;
      
      audio.src = url;
      console.log('[VOICE] Audio src set, blob size:', blob.size);
      
      audio.onended = () => {
        console.log('[VOICE] Audio playback ended successfully');
        URL.revokeObjectURL(url);
        this.currentAudio = null;
        resolve();
      };
      
      audio.onerror = (error) => {
        console.error('[VOICE] Audio element error:', error);
        URL.revokeObjectURL(url);
        this.currentAudio = null;
        reject(error);
      };
      
      console.log('[VOICE] Starting audio.play()...');
      audio.play()
        .then(() => {
          console.log('[VOICE] audio.play() promise resolved');
        })
        .catch((error) => {
          console.error('[VOICE] audio.play() failed:', error);
          URL.revokeObjectURL(url);
          this.currentAudio = null;
          reject(error);
        });
    });
  }

  /**
   * Speech-to-Text (file upload)
   */
  async transcribe(audioBlob, options = {}) {
    const {
      language = 'en',
      model = 'base'
    } = options;

    // Determine file extension from blob type
    let filename = 'audio.wav';
    if (audioBlob.type.includes('webm')) {
      filename = 'audio.webm';
    } else if (audioBlob.type.includes('ogg')) {
      filename = 'audio.ogg';
    } else if (audioBlob.type.includes('mp3')) {
      filename = 'audio.mp3';
    }

    const formData = new FormData();
    formData.append('file', audioBlob, filename);

    try {
      const response = await fetch(`${API_BASE}/voice/transcribe`, {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`STT failed (${response.status}): ${errorText}`);
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
