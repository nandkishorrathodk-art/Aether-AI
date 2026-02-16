import { useState, useEffect } from 'react';
import { io } from 'socket.io-client';
import { ThemeProvider, createTheme, CssBaseline, Box } from '@mui/material';
import Dashboard from './components/Dashboard';

const theme = createTheme({
    palette: {
        mode: 'dark',
        primary: { main: '#00f2ea' }, // Cyan
        secondary: { main: '#007aff' }, // Electric Blue
        background: { default: '#0a0a0a', paper: '#111' },
    },
    typography: {
        fontFamily: '"Orbitron", "Roboto", "Helvetica", "Arial", sans-serif',
    },
});

const socket = io('http://localhost:3001');

function App() {
    const [connected, setConnected] = useState(false);
    const [voiceData, setVoiceData] = useState(null);
    const [voiceStatus, setVoiceStatus] = useState("idle");

    useEffect(() => {
        socket.on('connect', () => {
            console.log('Connected to Aether Backend');
            setConnected(true);
        });

        socket.on('disconnect', () => {
            setConnected(false);
            setVoiceStatus("disconnected");
        });

        socket.on('voice_visualizer', (data) => {
            setVoiceData(data);
        });

        socket.on('voice_status', (data) => {
            console.log("Voice Status:", data.status, data);
            setVoiceStatus(data.status);
        });

        return () => {
            socket.off('connect');
            socket.off('disconnect');
            socket.off('voice_visualizer');
            socket.off('voice_status');
        };
    }, []);

    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <Box sx={{ height: '100vh', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                <Dashboard connected={connected} voiceData={voiceData} status={voiceStatus} />
            </Box>
        </ThemeProvider>
    );
}

export default App;
