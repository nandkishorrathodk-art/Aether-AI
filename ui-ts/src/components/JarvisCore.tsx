import { Box } from '@mui/material';
import { motion } from 'framer-motion';

const JarvisCore = ({ active }: { active: boolean }) => {
    return (
        <Box sx={{ position: 'relative', width: 400, height: 400, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            {/* Outer Ring - Keeping the tech vibe but softer blue */}
            <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                style={{
                    position: 'absolute',
                    width: '100%',
                    height: '100%',
                    border: '2px solid rgba(100, 200, 255, 0.3)', // Softer blue
                    borderRadius: '50%',
                    borderTopColor: 'transparent',
                    borderBottomColor: 'transparent'
                }}
            />

            {/* Inner Ring - Rotating Opposite */}
            <motion.div
                animate={{ rotate: -360 }}
                transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
                style={{
                    position: 'absolute',
                    width: '85%',
                    height: '85%',
                    border: '2px dashed rgba(255, 200, 255, 0.4)', // Pinkish hint for Megumi
                    borderRadius: '50%',
                }}
            />

            {/* Character Container */}
            <motion.div
                animate={{ scale: active ? [1, 1.05, 1] : 1 }}
                transition={{ duration: active ? 0.5 : 2, repeat: Infinity }}
                style={{
                    width: '70%',
                    height: '70%',
                    borderRadius: '50%',
                    overflow: 'hidden',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    backgroundColor: 'rgba(0, 50, 100, 0.3)',
                    border: '2px solid rgba(100, 200, 255, 0.8)',
                    boxShadow: active ? '0 0 40px rgba(100, 200, 255, 0.6)' : 'none'
                }}
            >
                <img
                    src="/megumi.png"
                    alt="Megumi AI"
                    style={{
                        width: '100%',
                        height: '100%',
                        objectFit: 'cover',
                        opacity: 0.9
                    }}
                    onError={(e) => {
                        e.currentTarget.onerror = null; // Prevent infinite loop
                        e.currentTarget.src = "https://api.dicebear.com/9.x/micah/svg?seed=Megumi&baseColor=f9c9b6&hair=0000ff&backgroundColor=b6e3f4";
                    }}
                />
            </motion.div>
        </Box>
    );
};

export default JarvisCore;
