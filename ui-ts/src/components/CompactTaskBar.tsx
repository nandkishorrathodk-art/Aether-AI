import { Box, Paper, Typography, IconButton } from '@mui/material';
import { Mic, Terminal, Settings, Wifi } from 'lucide-react';
import { motion } from 'framer-motion';

const CompactTaskBar = () => {
    return (
        <motion.div
            initial={{ y: 50, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 1 }}
        >
            <Paper sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 2,
                padding: '8px 20px',
                borderRadius: '20px',
                backgroundColor: 'rgba(20, 20, 20, 0.8)',
                backdropFilter: 'blur(10px)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                minWidth: 300
            }}>
                <IconButton color="primary" size="small">
                    <Mic size={18} />
                </IconButton>

                <Box sx={{ width: 1, height: 20, bgcolor: 'rgba(255,255,255,0.1)' }} />

                <Typography variant="body2" sx={{ color: '#aaa', fontSize: '0.8rem', flexGrow: 1, textAlign: 'center' }}>
                    AETHER SYSTEM ACTIVE
                </Typography>

                <Box sx={{ width: 1, height: 20, bgcolor: 'rgba(255,255,255,0.1)' }} />

                <IconButton size="small" sx={{ color: '#aaa' }}>
                    <Terminal size={16} />
                </IconButton>
                <IconButton size="small" sx={{ color: '#aaa' }}>
                    <Settings size={16} />
                </IconButton>

                <Box sx={{ ml: 1, display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <Wifi size={14} color="#00f2ea" />
                </Box>
            </Paper>
        </motion.div>
    );
};

export default CompactTaskBar;
