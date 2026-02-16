/**
 * Performance Monitoring Service
 * 
 * Optimized for Acer Swift Neo:
 * - CPU: Intel Core Ultra (10+ cores)
 * - RAM: 16GB DDR5
 * - SSD: 512GB NVMe
 * 
 * Features:
 * - Real-time system metrics
 * - Memory usage tracking
 * - CPU temperature monitoring
 * - Disk I/O tracking
 * - Auto-optimization recommendations
 */

import si from 'systeminformation';
import { EventEmitter } from 'events';
import { logger } from '../../utils/logger';
import type { PerformanceMetrics } from '../../types/api';

interface PerformanceHistory {
  timestamp: number;
  metrics: PerformanceMetrics;
}

class PerformanceService extends EventEmitter {
  private history: PerformanceHistory[] = [];
  private maxHistorySize = 100; // Keep last 100 samples
  private updateInterval: NodeJS.Timeout | null = null;
  private updateFrequency = 2000; // 2 seconds

  // Hardware limits for Acer Swift Neo
  private readonly HARDWARE_SPECS = {
    MAX_RAM_GB: 16,
    MAX_SSD_GB: 512,
    OPTIMAL_CPU_USAGE: 70, // Target max CPU usage
    OPTIMAL_RAM_USAGE: 75, // Target max RAM usage
    CRITICAL_TEMP: 85 // CPU temperature threshold
  };

  constructor() {
    super();
    logger.info('Performance Service initialized');
  }

  /**
   * Start performance monitoring
   */
  async start(): Promise<void> {
    logger.info('Starting performance monitoring...');

    // Initial metrics
    await this.updateMetrics();

    // Start periodic updates
    this.updateInterval = setInterval(async () => {
      await this.updateMetrics();
    }, this.updateFrequency);

    logger.info(`Performance monitoring started (${this.updateFrequency}ms interval)`);
  }

  /**
   * Stop performance monitoring
   */
  async stop(): Promise<void> {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
    logger.info('Performance monitoring stopped');
  }

  /**
   * Get current performance metrics
   */
  async getMetrics(): Promise<PerformanceMetrics> {
    try {
      // Get system information in parallel
      const [cpuData, memData, diskData, networkData, cpuTemp] = await Promise.all([
        si.currentLoad(),
        si.mem(),
        si.fsSize(),
        si.networkStats(),
        si.cpuTemperature()
      ]);

      // CPU metrics
      const cpuMetrics = {
        usage: Math.round(cpuData.currentLoad * 10) / 10,
        cores: cpuData.cpus?.length || 0,
        temperature: cpuTemp.main || undefined
      };

      // Memory metrics (convert to GB)
      const totalMemGB = Math.round(memData.total / (1024 ** 3) * 10) / 10;
      const usedMemGB = Math.round(memData.used / (1024 ** 3) * 10) / 10;
      const freeMemGB = Math.round(memData.free / (1024 ** 3) * 10) / 10;

      const memoryMetrics = {
        total: totalMemGB,
        used: usedMemGB,
        free: freeMemGB,
        percentage: Math.round((memData.used / memData.total) * 100 * 10) / 10
      };

      // Disk metrics (find main drive, usually C:)
      const mainDisk = diskData.find(d => d.mount === 'C:') || diskData[0];
      const totalDiskGB = Math.round(mainDisk.size / (1024 ** 3) * 10) / 10;
      const usedDiskGB = Math.round(mainDisk.used / (1024 ** 3) * 10) / 10;
      const freeDiskGB = Math.round((mainDisk.size - mainDisk.used) / (1024 ** 3) * 10) / 10;

      const diskMetrics = {
        total: totalDiskGB,
        used: usedDiskGB,
        free: freeDiskGB,
        percentage: Math.round((mainDisk.used / mainDisk.size) * 100 * 10) / 10
      };

      // Network metrics (sum all interfaces)
      const networkMetrics = {
        rx: networkData.reduce((sum, iface) => sum + (iface.rx_sec || 0), 0),
        tx: networkData.reduce((sum, iface) => sum + (iface.tx_sec || 0), 0)
      };

      const metrics: PerformanceMetrics = {
        cpu: cpuMetrics,
        memory: memoryMetrics,
        disk: diskMetrics,
        network: networkMetrics
      };

      return metrics;

    } catch (error) {
      logger.error('Error getting performance metrics:', error);
      throw error;
    }
  }

  /**
   * Update metrics and store in history
   */
  private async updateMetrics(): Promise<void> {
    try {
      const metrics = await this.getMetrics();

      // Add to history
      this.history.push({
        timestamp: Date.now(),
        metrics
      });

      // Trim history if needed
      if (this.history.length > this.maxHistorySize) {
        this.history = this.history.slice(-this.maxHistorySize);
      }

      // Emit event for real-time updates
      this.emit('metrics', metrics);

      // Check for alerts
      this.checkAlerts(metrics);

    } catch (error) {
      logger.error('Error updating metrics:', error);
    }
  }

  /**
   * Check for performance alerts
   */
  private checkAlerts(metrics: PerformanceMetrics): void {
    const alerts: string[] = [];

    // CPU alerts
    if (metrics.cpu.usage > this.HARDWARE_SPECS.OPTIMAL_CPU_USAGE) {
      alerts.push(`High CPU usage: ${metrics.cpu.usage}%`);
    }

    if (metrics.cpu.temperature && metrics.cpu.temperature > this.HARDWARE_SPECS.CRITICAL_TEMP) {
      alerts.push(`Critical CPU temperature: ${metrics.cpu.temperature}°C`);
    }

    // Memory alerts
    if (metrics.memory.percentage > this.HARDWARE_SPECS.OPTIMAL_RAM_USAGE) {
      alerts.push(`High memory usage: ${metrics.memory.percentage}% (${metrics.memory.used}GB/${metrics.memory.total}GB)`);
    }

    // Disk alerts
    if (metrics.disk.percentage > 90) {
      alerts.push(`Low disk space: ${metrics.disk.free}GB free`);
    }

    // Emit alerts
    if (alerts.length > 0) {
      this.emit('alerts', alerts);
      logger.warn('Performance alerts:', alerts);
    }
  }

  /**
   * Get performance history
   */
  getHistory(minutes: number = 5): PerformanceHistory[] {
    const cutoff = Date.now() - (minutes * 60 * 1000);
    return this.history.filter(h => h.timestamp >= cutoff);
  }

  /**
   * Get average metrics over time
   */
  getAverageMetrics(minutes: number = 5): Partial<PerformanceMetrics> {
    const history = this.getHistory(minutes);
    if (history.length === 0) return {};

    const sum = history.reduce((acc, h) => ({
      cpu: acc.cpu + h.metrics.cpu.usage,
      memory: acc.memory + h.metrics.memory.percentage,
      disk: acc.disk + h.metrics.disk.percentage
    }), { cpu: 0, memory: 0, disk: 0 });

    return {
      cpu: {
        usage: Math.round((sum.cpu / history.length) * 10) / 10,
        cores: history[0].metrics.cpu.cores,
        temperature: history[history.length - 1].metrics.cpu.temperature
      },
      memory: {
        total: history[history.length - 1].metrics.memory.total,
        used: history[history.length - 1].metrics.memory.used,
        free: history[history.length - 1].metrics.memory.free,
        percentage: Math.round((sum.memory / history.length) * 10) / 10
      },
      disk: {
        total: history[history.length - 1].metrics.disk.total,
        used: history[history.length - 1].metrics.disk.used,
        free: history[history.length - 1].metrics.disk.free,
        percentage: Math.round((sum.disk / history.length) * 10) / 10
      }
    };
  }

  /**
   * Get optimization recommendations
   */
  getRecommendations(): string[] {
    const recommendations: string[] = [];
    const latest = this.history[this.history.length - 1]?.metrics;

    if (!latest) return recommendations;

    // CPU recommendations
    if (latest.cpu.usage > this.HARDWARE_SPECS.OPTIMAL_CPU_USAGE) {
      recommendations.push('Reduce background processes or close unused applications');
    }

    // Memory recommendations
    if (latest.memory.percentage > this.HARDWARE_SPECS.OPTIMAL_RAM_USAGE) {
      recommendations.push('Clear cache or close memory-intensive applications');
      if (latest.memory.percentage > 90) {
        recommendations.push('Critical: Memory usage very high - system may slow down');
      }
    }

    // Disk recommendations
    if (latest.disk.percentage > 80) {
      recommendations.push(`Free up disk space (${latest.disk.free}GB remaining of ${latest.disk.total}GB)`);
    }

    // Temperature recommendations
    if (latest.cpu.temperature && latest.cpu.temperature > 75) {
      recommendations.push('CPU temperature elevated - ensure good ventilation');
    }

    return recommendations;
  }

  /**
   * Get system summary
   */
  getSummary(): {
    status: 'optimal' | 'good' | 'warning' | 'critical';
    message: string;
    metrics?: PerformanceMetrics;
  } {
    const latest = this.history[this.history.length - 1]?.metrics;

    if (!latest) {
      return {
        status: 'warning',
        message: 'No metrics available'
      };
    }

    // Determine overall status
    let status: 'optimal' | 'good' | 'warning' | 'critical' = 'optimal';
    const issues: string[] = [];

    if (latest.cpu.usage > 90 || latest.memory.percentage > 95) {
      status = 'critical';
      issues.push('Critical resource usage');
    } else if (latest.cpu.usage > this.HARDWARE_SPECS.OPTIMAL_CPU_USAGE || 
               latest.memory.percentage > this.HARDWARE_SPECS.OPTIMAL_RAM_USAGE) {
      status = 'warning';
      issues.push('High resource usage');
    } else if (latest.cpu.usage > 50 || latest.memory.percentage > 60) {
      status = 'good';
    }

    const message = issues.length > 0 
      ? issues.join(', ')
      : 'System performing optimally';

    return {
      status,
      message,
      metrics: latest
    };
  }
}

// Singleton instance
export const performanceService = new PerformanceService();
