import React from 'react';
import { Box, Typography, Chip } from '@mui/material';
import TranslateIcon from '@mui/icons-material/Translate';
import PsychopIcon from '@mui/icons-material/Psychology';

const LanguageStatusHUD = ({ language = 'en', status = 'idle' }) => {
    const languages = {
        'en': 'English (US)',
        'hi': 'Hindi (हिन्दी)',
    };

    const currentLangName = languages[language] || language.toUpperCase();

    if (status === 'idle') return null;

    return (
        <Box className="language-hud-container" sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 1.5,
            mt: 1,
            pt: 1,
            borderTop: '1px solid rgba(0, 212, 255, 0.1)',
        }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <TranslateIcon sx={{ fontSize: 14, color: '#00d4ff' }} />
                <Typography sx={{ fontSize: '10px', color: '#80c8e8', fontWeight: 600 }}>
                    DETECTION: <span style={{ color: '#fff' }}>{currentLangName}</span>
                </Typography>
            </Box>

            {status === 'thinking' && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }} className="thinking-pulse">
                    <PsychopIcon sx={{ fontSize: 14, color: '#a855f7' }} />
                    <Typography sx={{ fontSize: '10px', color: '#d8b4fe', fontWeight: 600 }}>
                        NEURAL REASONING...
                    </Typography>
                </Box>
            )}
        </Box>
    );
};

export default LanguageStatusHUD;
