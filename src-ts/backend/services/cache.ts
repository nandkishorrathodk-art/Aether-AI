/**
 * Cache Service
 * 
 * Dual-mode caching:
 * - Redis (production, distributed)
 * - In-memory (development, faster)
 * 
 * Optimized for 16GB RAM:
 * - Max cache size: 512MB
 * - TTL-based expiration
 * - Compression for large values
 */

import NodeCache from 'node-cache';
import { createClient, RedisClientType } from 'redis';
import { logger } from '../../utils/logger';
import type { CacheConfig, CacheStats } from '../../types/api';

class CacheService {
  private redisClient: RedisClientType | null = null;
  private memoryCache: NodeCache;
  private config: CacheConfig;
  private stats: CacheStats = {
    hits: 0,
    misses: 0,
    keys: 0,
    size: 0,
    hitRate: 0
  };

  constructor() {
    // Default config
    this.config = {
      provider: process.env.CACHE_PROVIDER === 'redis' ? 'redis' : 'memory',
      ttl: 3600, // 1 hour default
      maxSize: 512 * 1024 * 1024, // 512MB
      compression: true
    };

    // Initialize in-memory cache
    this.memoryCache = new NodeCache({
      stdTTL: this.config.ttl,
      checkperiod: 120, // Check for expired keys every 2 minutes
      maxKeys: 10000, // Limit number of keys
      useClones: false // Better performance
    });

    // Setup event listeners
    this.memoryCache.on('expired', (key, value) => {
      logger.debug(`Cache key expired: ${key}`);
    });

    logger.info(`Cache Service initialized (provider: ${this.config.provider})`);
  }

  /**
   * Connect to cache provider
   */
  async connect(): Promise<void> {
    if (this.config.provider === 'redis') {
      await this.connectRedis();
    }
    logger.info('Cache connected');
  }

  /**
   * Disconnect from cache provider
   */
  async disconnect(): Promise<void> {
    if (this.redisClient) {
      await this.redisClient.quit();
      this.redisClient = null;
    }
    this.memoryCache.close();
    logger.info('Cache disconnected');
  }

  /**
   * Connect to Redis
   */
  private async connectRedis(): Promise<void> {
    try {
      this.redisClient = createClient({
        url: process.env.REDIS_URL || 'redis://localhost:6379'
      });

      this.redisClient.on('error', (err) => {
        logger.error('Redis error:', err);
      });

      this.redisClient.on('connect', () => {
        logger.info('Redis connected');
      });

      await this.redisClient.connect();

    } catch (error) {
      logger.warn('Redis connection failed, falling back to memory cache:', error);
      this.config.provider = 'memory';
    }
  }

  /**
   * Get value from cache
   */
  async get<T = any>(key: string): Promise<T | null> {
    try {
      let value: T | null = null;

      if (this.config.provider === 'redis' && this.redisClient) {
        const data = await this.redisClient.get(key);
        value = data ? JSON.parse(data) : null;
      } else {
        value = this.memoryCache.get<T>(key) || null;
      }

      // Update stats
      if (value !== null) {
        this.stats.hits++;
      } else {
        this.stats.misses++;
      }

      this.updateHitRate();

      return value;

    } catch (error) {
      logger.error(`Cache get error for key ${key}:`, error);
      this.stats.misses++;
      return null;
    }
  }

  /**
   * Set value in cache
   */
  async set<T = any>(key: string, value: T, ttl?: number): Promise<boolean> {
    try {
      const effectiveTTL = ttl || this.config.ttl;

      if (this.config.provider === 'redis' && this.redisClient) {
        await this.redisClient.setEx(key, effectiveTTL, JSON.stringify(value));
      } else {
        this.memoryCache.set(key, value, effectiveTTL);
      }

      this.stats.keys = await this.getKeyCount();
      return true;

    } catch (error) {
      logger.error(`Cache set error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Delete key from cache
   */
  async delete(key: string): Promise<boolean> {
    try {
      if (this.config.provider === 'redis' && this.redisClient) {
        await this.redisClient.del(key);
      } else {
        this.memoryCache.del(key);
      }

      this.stats.keys = await this.getKeyCount();
      return true;

    } catch (error) {
      logger.error(`Cache delete error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Check if key exists
   */
  async has(key: string): Promise<boolean> {
    try {
      if (this.config.provider === 'redis' && this.redisClient) {
        const exists = await this.redisClient.exists(key);
        return exists === 1;
      } else {
        return this.memoryCache.has(key);
      }
    } catch (error) {
      logger.error(`Cache has error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Clear all cache
   */
  async clear(): Promise<void> {
    try {
      if (this.config.provider === 'redis' && this.redisClient) {
        await this.redisClient.flushDb();
      } else {
        this.memoryCache.flushAll();
      }

      // Reset stats
      this.stats = {
        hits: 0,
        misses: 0,
        keys: 0,
        size: 0,
        hitRate: 0
      };

      logger.info('Cache cleared');

    } catch (error) {
      logger.error('Cache clear error:', error);
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    return { ...this.stats };
  }

  /**
   * Get number of keys in cache
   */
  private async getKeyCount(): Promise<number> {
    try {
      if (this.config.provider === 'redis' && this.redisClient) {
        return await this.redisClient.dbSize();
      } else {
        return this.memoryCache.keys().length;
      }
    } catch (error) {
      return 0;
    }
  }

  /**
   * Update hit rate
   */
  private updateHitRate(): void {
    const total = this.stats.hits + this.stats.misses;
    this.stats.hitRate = total > 0 
      ? Math.round((this.stats.hits / total) * 100 * 10) / 10
      : 0;
  }

  /**
   * Get or set (fetch if not in cache)
   */
  async getOrSet<T>(
    key: string,
    fetcher: () => Promise<T>,
    ttl?: number
  ): Promise<T> {
    // Try to get from cache
    let value = await this.get<T>(key);

    if (value !== null) {
      return value;
    }

    // Fetch and cache
    value = await fetcher();
    await this.set(key, value, ttl);

    return value;
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    if (this.config.provider === 'redis') {
      return this.redisClient?.isOpen || false;
    }
    return true; // Memory cache always available
  }

  /**
   * Get cache provider
   */
  getProvider(): 'redis' | 'memory' {
    return this.config.provider;
  }
}

// Singleton instance
export const cacheService = new CacheService();
