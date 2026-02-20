import React, { useState, useRef, useEffect } from 'react';
import api from '../services/api';

function SimpleVoiceAssistant() {
  const [isRecording, setIsRecording] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [responseText, setResponseText] = useState('');

  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const audioRef = useRef(null);
  const streamRef = useRef(null);

  useEffect(() => {
    return () => {
      if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
        mediaRecorderRef.current.stop();
      }
      if (streamRef.current) {
        streamRef.current.getTracks().forEach(track => track.stop());
      }
    };
  }, []);

  const startRecording = async () => {
    try {
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.src = "";
      }
      setIsSpeaking(false);
      setTranscript('');
      setResponseText('');

      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;

      let options = { mimeType: 'audio/webm;codecs=opus' };
      if (!MediaRecorder.isTypeSupported(options.mimeType)) {
        options = { mimeType: 'audio/webm' };
        if (!MediaRecorder.isTypeSupported(options.mimeType)) {
          options = {}; // Fallback to browser default
        }
      }

      const mediaRecorder = new MediaRecorder(stream, options);

      mediaRecorderRef.current = mediaRecorder;
      audioChunksRef.current = [];

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunksRef.current.push(event.data);
        }
      };

      mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
        console.log(`Audio stopped. Size: ${audioBlob.size} bytes from ${audioChunksRef.current.length} chunks`);

        stream.getTracks().forEach(track => track.stop());
        streamRef.current = null;

        if (audioBlob.size > 0) {
          await processAudio(audioBlob);
        } else {
          console.error("Audio blob is empty");
          setTranscript("Error: Microphone didn't capture audio.");
          setIsProcessing(false);
        }
      };

      mediaRecorder.start(250); // Get chunks every 250ms to ensure data is collected
      setIsRecording(true);
    } catch (error) {
      console.error('Failed to start recording:', error);
      alert('Microphone access denied or unavailable. Please check permissions.');
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
    }
  };

  const processAudio = async (audioBlob) => {
    setIsProcessing(true);
    try {
      console.log('Transcribing audio...');
      const result = await api.transcribeAudio(audioBlob);

      if (result.text && result.text.trim()) {
        const text = result.text.trim();
        setTranscript(text);
        await handleUserInput(text);
      } else {
        console.log('No speech detected');
        setTranscript('[No speech detected]');
      }
    } catch (error) {
      console.error('Transcription failed:', error);
      setTranscript('[Transcription Failed]');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleUserInput = async (text) => {
    setIsProcessing(true);
    try {
      console.log('Getting AI response...');
      const conversationResult = await api.conversation(text, 'voice-session', true);
      const aiResponse = conversationResult.content || conversationResult.response || '';

      console.log('AI response:', aiResponse);
      setResponseText(aiResponse);

      if (aiResponse) {
        await speakResponse(aiResponse);
      }
    } catch (err) {
      console.error('Processing failed:', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const speakResponse = async (text) => {
    try {
      setIsSpeaking(true);
      console.log('Synthesizing speech...');

      const audioBlob = await api.synthesizeSpeech(text);
      const audioUrl = URL.createObjectURL(audioBlob);

      const audio = new Audio(audioUrl);
      audioRef.current = audio;

      audio.onended = () => {
        setIsSpeaking(false);
        URL.revokeObjectURL(audioUrl);
      };

      audio.onerror = (e) => {
        console.error('Audio playback error:', e);
        setIsSpeaking(false);
        URL.revokeObjectURL(audioUrl);
      };

      await audio.play();
      console.log('Audio playback started successfully.');
    } catch (err) {
      console.error('Speech synthesis/playback failed:', err);
      setIsSpeaking(false);
    }
  };

  const handleInteraction = () => {
    if (isProcessing) return;

    if (isSpeaking) {
      // Stop speaking if user clicks while AI is talking
      if (audioRef.current) {
        audioRef.current.pause();
        audioRef.current.src = "";
      }
      setIsSpeaking(false);
      return;
    }

    if (isRecording) {
      stopRecording();
    } else {
      startRecording();
    }
  };

  return (
    <div
      onClick={handleInteraction}
      style={{
        width: '100%',
        textAlign: 'center',
        cursor: isProcessing ? 'wait' : 'pointer',
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        WebkitAppRegion: 'no-drag' // IMPORTANT: Allows clicking instead of window dragging
      }}
    >
      <div style={{ color: '#ccc', fontStyle: 'italic', fontSize: '0.9rem' }}>
        {isRecording ? "Listening, Sir... (Click to Send)" : isSpeaking ? "Speaking..." : isProcessing ? "Processing Data..." : "Awaiting Systems (Click to Talk)"}
      </div>
      {transcript && (
        <div style={{ color: '#fff', fontSize: '0.8rem', opacity: 0.7 }}>
          "{transcript}"
        </div>
      )}
      {responseText && isSpeaking && (
        <div style={{ color: '#00ffff', fontSize: '0.85rem' }}>
          {responseText.length > 50 ? responseText.substring(0, 50) + '...' : responseText}
        </div>
      )}
    </div>
  );
}

export default SimpleVoiceAssistant;
