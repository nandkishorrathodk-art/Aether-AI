/**
 * API Type Definitions for Aether AI
 * 
 * Comprehensive TypeScript types for all API interactions
 */

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp: number;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// Voice Command Types
export interface VoiceCommand {
  id: string;
  text: string;
  intent: string;
  confidence: number;
  timestamp: number;
  sessionId: string;
}

export interface VoiceCommandResult {
  commandId: string;
  status: 'success' | 'error' | 'pending';
  response: string;
  executionTime: number;
  data?: any;
}

// Session Types
export interface Session {
  id: string;
  userId: string;
  startTime: number;
  lastActivity: number;
  metadata: Record<string, any>;
}

// Performance Types
export interface PerformanceMetrics {
  cpu: {
    usage: number;
    cores: number;
    temperature?: number;
  };
  memory: {
    total: number;
    used: number;
    free: number;
    percentage: number;
  };
  disk: {
    total: number;
    used: number;
    free: number;
    percentage: number;
  };
  network: {
    rx: number; // bytes received
    tx: number; // bytes transmitted
  };
}

// WebSocket Message Types
export enum WSMessageType {
  VOICE_COMMAND = 'voice_command',
  SYSTEM_STATUS = 'system_status',
  NOTIFICATION = 'notification',
  ERROR = 'error',
  PERFORMANCE_UPDATE = 'performance_update',
  CHAT_MESSAGE = 'chat_message'
}

export interface WSMessage<T = any> {
  type: WSMessageType;
  data: T;
  timestamp: number;
  id: string;
}

// Cache Types
export interface CacheConfig {
  provider: 'redis' | 'memory';
  ttl: number; // seconds
  maxSize: number; // bytes
  compression: boolean;
}

export interface CacheStats {
  hits: number;
  misses: number;
  keys: number;
  size: number; // bytes
  hitRate: number; // percentage
}

// Task Types
export interface Task {
  id: string;
  type: 'automation' | 'script' | 'ai' | 'file';
  command: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  priority: 'low' | 'normal' | 'high' | 'urgent';
  createdAt: number;
  startedAt?: number;
  completedAt?: number;
  result?: any;
  error?: string;
}

// File Types
export interface FileInfo {
  path: string;
  name: string;
  size: number;
  type: string;
  modified: number;
  created: number;
  hash?: string;
}

export interface FileOperation {
  operation: 'read' | 'write' | 'delete' | 'move' | 'copy';
  source: string;
  destination?: string;
  options?: Record<string, any>;
}

// AI Provider Types
export interface AIProvider {
  name: string;
  models: string[];
  available: boolean;
  costPerToken?: number;
  maxTokens: number;
  supportsStreaming: boolean;
}

export interface AIRequest {
  prompt: string;
  provider?: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  stream?: boolean;
  sessionId?: string;
}

export interface AIResponse {
  text: string;
  provider: string;
  model: string;
  tokensUsed: number;
  cost: number;
  latency: number;
  cached: boolean;
}

// Memory Types
export interface Memory {
  id: string;
  content: string;
  type: 'user' | 'conversation' | 'fact' | 'task';
  embedding?: number[];
  metadata: Record<string, any>;
  createdAt: number;
  relevance?: number;
}

// System Configuration
export interface SystemConfig {
  voice: {
    wakeWord: string;
    sttProvider: 'local' | 'cloud';
    ttsProvider: 'local' | 'cloud';
    language: string;
  };
  ai: {
    defaultProvider: string;
    temperature: number;
    maxTokens: number;
  };
  performance: {
    maxCpuUsage: number;
    maxMemoryUsage: number;
    cacheEnabled: boolean;
  };
  hardware: {
    cpu: string;
    ram: number;
    storage: number;
  };
}

// Error Types
export interface AppError {
  code: string;
  message: string;
  details?: any;
  stack?: string;
  timestamp: number;
}

// Health Check
export interface HealthCheck {
  status: 'healthy' | 'degraded' | 'unhealthy';
  uptime: number;
  version: string;
  services: {
    python: boolean;
    typescript: boolean;
    redis?: boolean;
    database: boolean;
  };
  metrics: PerformanceMetrics;
}

// Rate Limiting
export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number; // timestamp
  retryAfter?: number; // seconds
}
