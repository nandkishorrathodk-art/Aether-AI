import { Box, Typography } from '@mui/material';
import JarvisCore from './JarvisCore';
import CompactTaskBar from './CompactTaskBar';
import VoiceVisualizer from './VoiceVisualizer';

interface DashboardProps {
    connected: boolean;
    voiceData: any;
    status: string;
}

const Dashboard = ({ connected, voiceData, status }: DashboardProps) => {
    // Map status to color
    const getStatusColor = (s: string) => {
        switch (s) {
            case 'listening': return '#00ff00'; // Green
            case 'processing': return '#ffff00'; // Yellow
            case 'speaking': return '#00f2ea'; // Cyan
            case 'error': return '#ff0000'; // Red
            default: return '#666'; // Grey
        }
    };

    return (
        <Box sx={{
            flexGrow: 1,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            position: 'relative'
        }}>
            {/* Background Grid/Effects */}
            <Box sx={{
                position: 'absolute',
                top: 0, left: 0, right: 0, bottom: 0,
                backgroundImage: 'radial-gradient(circle at center, rgba(0, 242, 234, 0.1) 0%, rgba(0,0,0,0) 70%)',
                zIndex: 0
            }} />

            {/* Main Core */}
            <Box sx={{ zIndex: 1, position: 'relative' }}>
                <JarvisCore active={!!voiceData} />
            </Box>

            {/* Status Indicator (Requested Feature) */}
            <Typography variant="h5" sx={{
                position: 'absolute',
                top: '20%',
                color: getStatusColor(status),
                textTransform: 'uppercase',
                letterSpacing: 4,
                fontWeight: 'bold',
                textShadow: `0 0 10px ${getStatusColor(status)}`,
                zIndex: 5
            }}>
                {status === 'idle' ? '' : status}
            </Typography>

            {/* Voice Viz */}
            <Box sx={{ position: 'absolute', bottom: '20%', width: '80%', height: '100px', zIndex: 2 }}>
                <VoiceVisualizer data={voiceData} />
            </Box>

            {/* System Status */}
            <Typography variant="caption" sx={{
                position: 'absolute',
                top: 10,
                right: 10,
                color: connected ? 'success.main' : 'error.main'
            }}>
                SYSTEM: {connected ? 'ONLINE' : 'OFFLINE'}
            </Typography>

            {/* Compact Taskbar at bottom */}
            <Box sx={{ position: 'absolute', bottom: 10, zIndex: 10 }}>
                <CompactTaskBar />
            </Box>
        </Box>
    );
};

export default Dashboard;
