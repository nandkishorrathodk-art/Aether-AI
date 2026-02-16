import { useRef, useEffect } from 'react';
import { Box } from '@mui/material';

const VoiceVisualizer = ({ data }: { data: number[] | null }) => {
    const canvasRef = useRef<HTMLCanvasElement>(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Animation loop (simulate if no data, or visualize data)
        let animationId: number;

        const draw = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            ctx.lineWidth = 2;
            ctx.strokeStyle = '#00f2ea';
            ctx.beginPath();

            const width = canvas.width;
            const height = canvas.height;
            const centerY = height / 2;

            // Use real data or simulate idle wave
            if (data && data.length > 0) {
                // Real visualization logic would go here
                // For now, simpler wave
                for (let x = 0; x < width; x++) {
                    const y = centerY + Math.sin(x * 0.05 + Date.now() * 0.01) * (data[x % data.length] || 10);
                    x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
                }
            } else {
                // Idle wave
                for (let x = 0; x < width; x++) {
                    const y = centerY + Math.sin(x * 0.02 + Date.now() * 0.005) * 10;
                    x === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
                }
            }

            ctx.stroke();
            animationId = requestAnimationFrame(draw);
        };

        draw();

        return () => cancelAnimationFrame(animationId);
    }, [data]);

    return (
        <Box sx={{ width: '100%', height: '100%' }}>
            <canvas
                ref={canvasRef}
                width={600}
                height={100}
                style={{ width: '100%', height: '100%' }}
            />
        </Box>
    );
};

export default VoiceVisualizer;
