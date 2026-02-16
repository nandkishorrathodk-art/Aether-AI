import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from 'redis';
import { spawn } from 'child_process';
import path from 'path';

dotenv.config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: ["http://localhost:5173", "http://localhost:3000"],
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3001;

// Redis Client
const redisClient = createClient();
redisClient.on('error', (err) => {
    // Suppress connection errors if not running
    if (err.code === 'ECONNREFUSED') return;
    console.log('Redis Client Error', err)
});

let redisConnected = false;

(async () => {
    try {
        await redisClient.connect();
        redisConnected = true;
        console.log('✅ Redis Connected');
    } catch (e) {
        console.log('⚠️ Redis Not Found - Using In-Memory Fallback');
    }
})();

// Middleware
app.use(cors());
app.use(express.json());

// Socket.IO Logic
io.on('connection', (socket) => {
    console.log('UI Connected:', socket.id);

    socket.on('voice_data', (data) => {
        // Broadcast for visualization
        socket.broadcast.emit('voice_visualizer', data);
        // TODO: Send to Python for processing
    });

    socket.on('command', (cmd) => {
        console.log('Command received:', cmd);
        // TODO: Forward to Python
    });

    socket.on('disconnect', () => {
        console.log('UI Disconnected:', socket.id);
    });
});

// Python Bridge (Spawn the Python backend if not running, or just communicate)
// For this hybrid setup, we'll assume Python runs separately or is spawned here.
// Let's spawn it for seamless experience.

// Python Bridge (Spawn the Python backend if not running, or just communicate)
const pythonExec = process.env.PYTHON_PATH || 'python';
console.log(`Using Python Interpreter: ${pythonExec}`);

const pythonProcess = spawn(pythonExec, ['src/main.py'], {
    cwd: path.resolve(__dirname, '../../'), // Go up to project root (src-ts/src -> src-ts -> root)
    stdio: ['pipe', 'pipe', 'pipe'], // Pipe stdio
    env: { ...process.env, PYTHONIOENCODING: 'utf-8' } // Force UTF-8 in the spawned process
});

pythonProcess.stdout.on('data', (data) => {
    const msg = data.toString();
    try {
        const json = JSON.parse(msg);
        if (json.type === 'status') {
            // Voice Status Update (listening, speaking, etc.)
            console.log(`[VOICE]: ${json.status}`);
            io.emit('voice_status', json);
        } else {
            // Other JSON logs
            console.log(`[PYTHON JSON]:`, json);
            io.emit('system_log', json);
        }
    } catch (e) {
        // Plain text log
        console.log(`[PYTHON]: ${msg}`);
        io.emit('system_log', msg);
    }
});

pythonProcess.stderr.on('data', (data) => {
    console.error(`[PYTHON ERR]: ${data}`);
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', mode: 'hybrid' });
});

const startServer = (port: number) => {
    const server = createServer(app);

    server.listen(port, () => {
        console.log(`🚀 Aether Hybrid Backend running on port ${port}`);
        io.attach(server);
    });

    server.on('error', (err: any) => {
        if (err.code === 'EADDRINUSE') {
            console.log(`⚠️ Port ${port} in use, trying ${port + 1}...`);
            startServer(port + 1);
        } else {
            console.error('Server Error:', err);
        }
    });
};

startServer(Number(PORT));
