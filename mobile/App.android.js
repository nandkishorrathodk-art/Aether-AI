import React, { useState, useEffect } from 'react';
import {
  StyleSheet,
  View,
  Text,
  TouchableOpacity,
  Animated,
  StatusBar,
  PermissionsAndroid,
  Platform,
} from 'react-native';
import Icon from 'react-native-vector-icons/MaterialIcons';
import Voice from '@react-native-voice/voice';
import Tts from 'react-native-tts';

const AetherAndroidApp = () => {
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [response, setResponse] = useState('');
  const [hasPermission, setHasPermission] = useState(false);
  
  const pulseAnim = new Animated.Value(1);

  useEffect(() => {
    requestMicrophonePermission();
    initializeVoice();
    playWelcomeGreeting();
    
    return () => {
      Voice.destroy().then(Voice.removeAllListeners);
    };
  }, []);

  const requestMicrophonePermission = async () => {
    if (Platform.OS === 'android') {
      try {
        const granted = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.RECORD_AUDIO,
          {
            title: 'Aether AI Microphone Permission',
            message: 'Aether AI needs access to your microphone for voice commands',
            buttonNeutral: 'Ask Me Later',
            buttonNegative: 'Cancel',
            buttonPositive: 'OK',
          }
        );
        setHasPermission(granted === PermissionsAndroid.RESULTS.GRANTED);
      } catch (err) {
        console.warn(err);
      }
    }
  };

  const initializeVoice = () => {
    Voice.onSpeechStart = () => setIsListening(true);
    Voice.onSpeechEnd = () => setIsListening(false);
    Voice.onSpeechResults = (e) => {
      if (e.value && e.value[0]) {
        setTranscript(e.value[0]);
        processVoiceCommand(e.value[0]);
      }
    };
    Voice.onSpeechError = (e) => console.error(e);
  };

  const playWelcomeGreeting = async () => {
    setIsSpeaking(true);
    setResponse('Hello sir, at your service!');
    
    Tts.speak('Hello sir, at your service! How may I help you today?');
    
    setTimeout(() => {
      setIsSpeaking(false);
      setResponse('');
    }, 5000);
  };

  const processVoiceCommand = async (command) => {
    try {
      // Call backend API
      const res = await fetch('http://localhost:8000/api/v1/voice-commands/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      });
      
      const data = await res.json();
      
      setResponse(data.response || 'Command processed');
      setIsSpeaking(true);
      
      // Speak response
      Tts.speak(data.response || 'Command processed');
      
      setTimeout(() => {
        setIsSpeaking(false);
        setResponse('');
      }, 5000);
    } catch (error) {
      console.error('API Error:', error);
      setResponse('Network error. Please check connection.');
    }
  };

  const toggleListening = async () => {
    if (!hasPermission) {
      await requestMicrophonePermission();
      return;
    }

    if (isListening) {
      Voice.stop();
      setIsListening(false);
    } else {
      try {
        await Voice.start('en-US');
        setIsListening(true);
        startPulseAnimation();
      } catch (e) {
        console.error(e);
      }
    }
  };

  const startPulseAnimation = () => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, {
          toValue: 1.3,
          duration: 800,
          useNativeDriver: true,
        }),
        Animated.timing(pulseAnim, {
          toValue: 1,
          duration: 800,
          useNativeDriver: true,
        }),
      ])
    ).start();
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#0f172a" />
      
      {/* Header */}
      <View style={styles.header}>
        <Icon name="settings-voice" size={32} color="#6366f1" />
        <Text style={styles.title}>Aether AI</Text>
      </View>

      {/* Status */}
      <Text style={styles.status}>
        {isListening ? '🎤 Listening...' : '🎤 Tap to Speak'}
      </Text>

      {/* Mic Button */}
      <View style={styles.micContainer}>
        <Animated.View style={{ transform: [{ scale: pulseAnim }] }}>
          <TouchableOpacity
            style={[
              styles.micButton,
              isListening && styles.micButtonActive,
            ]}
            onPress={toggleListening}
            activeOpacity={0.8}
          >
            <Icon
              name={isListening ? 'mic' : 'mic-none'}
              size={80}
              color="white"
            />
          </TouchableOpacity>
        </Animated.View>
      </View>

      {/* Transcript */}
      {transcript !== '' && (
        <View style={styles.messageBox}>
          <Text style={styles.messageLabel}>You said:</Text>
          <Text style={styles.messageText}>{transcript}</Text>
        </View>
      )}

      {/* Response */}
      {response !== '' && (
        <View style={[styles.messageBox, styles.responseBox]}>
          <Text style={styles.messageLabel}>Aether:</Text>
          <Text style={styles.messageText}>{response}</Text>
          {isSpeaking && (
            <Icon name="volume-up" size={24} color="#8b5cf6" />
          )}
        </View>
      )}

      {/* Footer */}
      <View style={styles.footer}>
        <Text style={styles.footerText}>
          Say "Aether" followed by your command
        </Text>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0f172a',
    alignItems: 'center',
    justifyContent: 'space-around',
    padding: 20,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginTop: 20,
  },
  title: {
    fontSize: 28,
    fontWeight: '700',
    color: '#f1f5f9',
  },
  status: {
    fontSize: 20,
    fontWeight: '600',
    color: '#94a3b8',
    marginTop: 20,
  },
  micContainer: {
    marginVertical: 40,
  },
  micButton: {
    width: 180,
    height: 180,
    borderRadius: 90,
    backgroundColor: '#1e293b',
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 10 },
    shadowOpacity: 0.3,
    shadowRadius: 20,
    elevation: 10,
  },
  micButtonActive: {
    backgroundColor: '#6366f1',
    shadowColor: '#6366f1',
    shadowOpacity: 0.6,
  },
  messageBox: {
    backgroundColor: 'rgba(30, 41, 59, 0.8)',
    borderRadius: 16,
    padding: 16,
    width: '100%',
    marginVertical: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#6366f1',
  },
  responseBox: {
    borderLeftColor: '#8b5cf6',
  },
  messageLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#94a3b8',
    marginBottom: 4,
  },
  messageText: {
    fontSize: 16,
    color: '#f1f5f9',
    lineHeight: 24,
  },
  footer: {
    marginBottom: 20,
  },
  footerText: {
    fontSize: 14,
    color: '#64748b',
    textAlign: 'center',
  },
});

export default AetherAndroidApp;
