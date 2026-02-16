/**
 * Advanced Logger with Winston
 * 
 * Features:
 * - File and console logging
 * - Log rotation
 * - Performance optimized
 * - Color-coded output
 */

import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Ensure logs directory exists
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format
const customFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.printf(({ timestamp, level, message, stack }) => {
    let log = `${timestamp} [${level.toUpperCase()}] ${message}`;
    if (stack) {
      log += `\n${stack}`;
    }
    return log;
  })
);

// Create logger
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: customFormat,
  transports: [
    // Console transport with colors
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        customFormat
      )
    }),

    // File transport for all logs
    new winston.transports.File({
      filename: path.join(logsDir, 'aether-ts.log'),
      maxsize: 10485760, // 10MB
      maxFiles: 5,
      tailable: true
    }),

    // Separate file for errors
    new winston.transports.File({
      filename: path.join(logsDir, 'aether-ts-error.log'),
      level: 'error',
      maxsize: 10485760, // 10MB
      maxFiles: 3,
      tailable: true
    })
  ]
});

// Performance logger
export class PerformanceLogger {
  private timers: Map<string, number> = new Map();

  start(label: string): void {
    this.timers.set(label, Date.now());
  }

  end(label: string): number {
    const startTime = this.timers.get(label);
    if (!startTime) {
      logger.warn(`No timer found for: ${label}`);
      return 0;
    }

    const duration = Date.now() - startTime;
    this.timers.delete(label);

    logger.debug(`[PERF] ${label}: ${duration}ms`);
    return duration;
  }

  async measure<T>(label: string, fn: () => Promise<T>): Promise<T> {
    this.start(label);
    try {
      const result = await fn();
      this.end(label);
      return result;
    } catch (error) {
      this.end(label);
      throw error;
    }
  }
}

export const perfLogger = new PerformanceLogger();
