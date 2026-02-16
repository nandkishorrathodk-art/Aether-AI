import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  TextField,
  IconButton,
  Paper,
  Typography,
  CircularProgress,
  Avatar,
  Chip,
} from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import PersonIcon from '@mui/icons-material/Person';
import api from '../services/api';

function ChatInterface({ sessionId, onError }) {
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [provider, setProvider] = useState(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    loadHistory();
  }, [sessionId]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadHistory = async () => {
    try {
      const data = await api.getConversationHistory(sessionId, 50);
      if (data.messages) {
        setMessages(data.messages);
      }
    } catch (error) {
      console.error('Failed to load history:', error);
    }
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || isLoading) return;

    const userMessage = {
      role: 'user',
      content: inputMessage,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const response = await api.conversation(inputMessage, sessionId, true);
      
      const assistantMessage = {
        role: 'assistant',
        content: response.response,
        timestamp: new Date().toISOString(),
        metadata: {
          provider: response.provider,
          model: response.model,
          intent: response.intent,
          tokens: response.tokens_used,
          cost: response.cost,
        },
      };

      setMessages((prev) => [...prev, assistantMessage]);
      setProvider(response.provider);

      if (response.cost > 0) {
        console.log(`Cost: $${response.cost.toFixed(6)} | Tokens: ${response.tokens_used}`);
      }
    } catch (error) {
      onError?.(error.message);
      
      const errorMessage = {
        role: 'assistant',
        content: `Sorry, I encountered an error: ${error.message}`,
        timestamp: new Date().toISOString(),
        isError: true,
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        bgcolor: 'background.default',
      }}
    >
      <Box
        sx={{
          flex: 1,
          overflowY: 'auto',
          p: 2,
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
        }}
      >
        {messages.length === 0 && (
          <Box
            sx={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              height: '100%',
              color: 'text.secondary',
            }}
          >
            <SmartToyIcon sx={{ fontSize: 64, mb: 2, opacity: 0.5 }} />
            <Typography variant="h6">How can I assist you today?</Typography>
            <Typography variant="body2" sx={{ mt: 1 }}>
              Ask me anything or try voice input with Ctrl+Space
            </Typography>
          </Box>
        )}

        {messages.map((message, index) => (
          <Box
            key={index}
            sx={{
              display: 'flex',
              justifyContent: message.role === 'user' ? 'flex-end' : 'flex-start',
              gap: 1,
            }}
          >
            {message.role === 'assistant' && (
              <Avatar sx={{ bgcolor: 'primary.main' }}>
                <SmartToyIcon />
              </Avatar>
            )}
            
            <Paper
              elevation={1}
              sx={{
                maxWidth: '70%',
                p: 2,
                bgcolor: message.role === 'user' ? 'primary.light' : 'background.paper',
                color: message.role === 'user' ? 'primary.contrastText' : 'text.primary',
                borderColor: message.isError ? 'error.main' : 'transparent',
                borderWidth: message.isError ? 1 : 0,
                borderStyle: 'solid',
              }}
            >
              <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                {message.content}
              </Typography>
              
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 1 }}>
                <Typography variant="caption" sx={{ opacity: 0.7 }}>
                  {formatTimestamp(message.timestamp)}
                </Typography>
                
                {message.metadata && (
                  <Box sx={{ display: 'flex', gap: 0.5 }}>
                    {message.metadata.provider && (
                      <Chip
                        label={message.metadata.provider}
                        size="small"
                        sx={{ height: 20, fontSize: '0.7rem' }}
                      />
                    )}
                    {message.metadata.intent && (
                      <Chip
                        label={message.metadata.intent}
                        size="small"
                        color="secondary"
                        sx={{ height: 20, fontSize: '0.7rem' }}
                      />
                    )}
                  </Box>
                )}
              </Box>
            </Paper>

            {message.role === 'user' && (
              <Avatar sx={{ bgcolor: 'secondary.main' }}>
                <PersonIcon />
              </Avatar>
            )}
          </Box>
        ))}

        {isLoading && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Avatar sx={{ bgcolor: 'primary.main' }}>
              <SmartToyIcon />
            </Avatar>
            <Paper elevation={1} sx={{ p: 2 }}>
              <CircularProgress size={24} />
            </Paper>
          </Box>
        )}

        <div ref={messagesEndRef} />
      </Box>

      <Box sx={{ p: 2, bgcolor: 'background.paper', borderTop: 1, borderColor: 'divider' }}>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <TextField
            fullWidth
            multiline
            maxRows={4}
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Type your message..."
            disabled={isLoading}
            variant="outlined"
            size="small"
          />
          <IconButton
            color="primary"
            onClick={handleSendMessage}
            disabled={!inputMessage.trim() || isLoading}
            sx={{ alignSelf: 'flex-end' }}
          >
            <SendIcon />
          </IconButton>
        </Box>
        
        {provider && (
          <Typography variant="caption" sx={{ mt: 0.5, display: 'block', color: 'text.secondary' }}>
            Using: {provider}
          </Typography>
        )}
      </Box>
    </Box>
  );
}

export default ChatInterface;
