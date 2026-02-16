/**
 * Aether AI - TypeScript Backend Server
 * 
 * High-performance Node.js server with Express and Socket.IO
 * Optimized for Acer Swift Neo (16GB RAM, 512GB SSD)
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import dotenv from 'dotenv';

import { logger } from '../utils/logger';
import { performanceService } from './services/performance';
import { cacheService } from './services/cache';
import { realtimeRoutes } from './routes/realtime';
import { fileRoutes } from './routes/files';
import { cacheRoutes } from './routes/cache';
import { rateLimiter } from './middleware/ratelimit';
import type { AppError, HealthCheck } from '../types/api';

// Load environment variables
dotenv.config();

const PORT = process.env.TS_PORT || 3001;
const PYTHON_API_URL = process.env.PYTHON_API_URL || 'http://127.0.0.1:8000';

class AetherServer {
  private app: Express;
  private httpServer: ReturnType<typeof createServer>;
  private io: SocketIOServer;
  private startTime: number;

  constructor() {
    this.app = express();
    this.httpServer = createServer(this.app);
    this.io = new SocketIOServer(this.httpServer, {
      cors: {
        origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
        methods: ['GET', 'POST'],
        credentials: true
      },
      transports: ['websocket', 'polling']
    });
    this.startTime = Date.now();

    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocket();
    this.setupErrorHandlers();
  }

  private setupMiddleware(): void {
    // Security
    this.app.use(helmet({
      contentSecurityPolicy: false, // Disable for development
      crossOriginEmbedderPolicy: false
    }));

    // CORS
    this.app.use(cors({
      origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
      credentials: true
    }));

    // Compression for responses
    this.app.use(compression());

    // Body parsing
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    // Logging
    this.app.use(morgan('combined', {
      stream: { write: (message) => logger.info(message.trim()) }
    }));

    // Rate limiting
    this.app.use(rateLimiter);

    logger.info('Middleware configured');
  }

  private setupRoutes(): void {
    // Health check
    this.app.get('/health', async (req: Request, res: Response) => {
      const metrics = await performanceService.getMetrics();
      const cacheStats = cacheService.getStats();

      const health: HealthCheck = {
        status: 'healthy',
        uptime: Date.now() - this.startTime,
        version: '0.2.0',
        services: {
          python: true, // Will check actual status
          typescript: true,
          redis: cacheService.isConnected(),
          database: true
        },
        metrics
      };

      res.json(health);
    });

    // Root endpoint
    this.app.get('/', (req: Request, res: Response) => {
      res.json({
        name: 'Aether AI TypeScript Backend',
        version: '0.2.0',
        status: 'running',
        uptime: Date.now() - this.startTime,
        endpoints: {
          health: '/health',
          realtime: '/api/realtime',
          files: '/api/files',
          cache: '/api/cache',
          performance: '/api/performance'
        }
      });
    });

    // API Routes
    this.app.use('/api/realtime', realtimeRoutes);
    this.app.use('/api/files', fileRoutes);
    this.app.use('/api/cache', cacheRoutes);

    // Performance endpoint
    this.app.get('/api/performance', async (req: Request, res: Response) => {
      try {
        const metrics = await performanceService.getMetrics();
        res.json({ success: true, data: metrics });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: 'Failed to get performance metrics'
        });
      }
    });

    logger.info('Routes configured');
  }

  private setupWebSocket(): void {
    this.io.on('connection', (socket) => {
      logger.info(`WebSocket client connected: ${socket.id}`);

      // Send initial performance metrics
      performanceService.getMetrics().then(metrics => {
        socket.emit('performance', metrics);
      });

      // Performance updates every 2 seconds
      const performanceInterval = setInterval(async () => {
        const metrics = await performanceService.getMetrics();
        socket.emit('performance', metrics);
      }, 2000);

      // Voice command handler
      socket.on('voice_command', async (data) => {
        logger.info(`Voice command received: ${data.text}`);
        socket.emit('voice_command_received', {
          commandId: data.id,
          status: 'processing'
        });

        // Forward to Python API for processing
        try {
          const axios = (await import('axios')).default;
          const response = await axios.post(
            `${PYTHON_API_URL}/api/v1/voice-commands/execute`,
            data
          );

          socket.emit('voice_command_result', {
            commandId: data.id,
            status: 'success',
            result: response.data
          });
        } catch (error: any) {
          socket.emit('voice_command_result', {
            commandId: data.id,
            status: 'error',
            error: error.message
          });
        }
      });

      // Disconnect handler
      socket.on('disconnect', () => {
        logger.info(`WebSocket client disconnected: ${socket.id}`);
        clearInterval(performanceInterval);
      });
    });

    logger.info('WebSocket configured');
  }

  private setupErrorHandlers(): void {
    // 404 handler
    this.app.use((req: Request, res: Response) => {
      res.status(404).json({
        success: false,
        error: 'Not Found',
        message: `Cannot ${req.method} ${req.path}`
      });
    });

    // Global error handler
    this.app.use((err: AppError, req: Request, res: Response, next: NextFunction) => {
      logger.error('Server error:', err);

      res.status(500).json({
        success: false,
        error: err.message || 'Internal Server Error',
        details: process.env.NODE_ENV === 'development' ? err.stack : undefined
      });
    });

    logger.info('Error handlers configured');
  }

  public async start(): Promise<void> {
    try {
      // Initialize services
      await cacheService.connect();
      await performanceService.start();

      // Start server
      this.httpServer.listen(PORT, () => {
        logger.info(`=================================================`);
        logger.info(`Aether AI TypeScript Server`);
        logger.info(`=================================================`);
        logger.info(`Server running on: http://localhost:${PORT}`);
        logger.info(`WebSocket ready on: ws://localhost:${PORT}`);
        logger.info(`Python API: ${PYTHON_API_URL}`);
        logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
        logger.info(`=================================================`);
      });

      // Graceful shutdown
      process.on('SIGTERM', () => this.shutdown());
      process.on('SIGINT', () => this.shutdown());

    } catch (error) {
      logger.error('Failed to start server:', error);
      process.exit(1);
    }
  }

  private async shutdown(): Promise<void> {
    logger.info('Shutting down gracefully...');

    // Close WebSocket connections
    this.io.close();

    // Stop services
    await performanceService.stop();
    await cacheService.disconnect();

    // Close HTTP server
    this.httpServer.close(() => {
      logger.info('Server shut down');
      process.exit(0);
    });

    // Force exit after 10 seconds
    setTimeout(() => {
      logger.error('Forced shutdown');
      process.exit(1);
    }, 10000);
  }

  public getIO(): SocketIOServer {
    return this.io;
  }
}

// Create and start server
const server = new AetherServer();
server.start().catch((error) => {
  logger.error('Fatal error:', error);
  process.exit(1);
});

export { server };
