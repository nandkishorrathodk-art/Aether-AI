//
//  AetherModels.swift
//  Aether AI - Core Data Models
//
//  Optimized for Apple Silicon (M1/M2/M3)
//

import Foundation

// MARK: - Voice Command Models

struct VoiceCommand: Codable, Identifiable {
    let id: String
    let text: String
    let intent: String
    let confidence: Double
    let timestamp: Date
    let sessionId: String
    
    enum CodingKeys: String, CodingKey {
        case id, text, intent, confidence, timestamp
        case sessionId = "session_id"
    }
}

struct VoiceCommandResult: Codable {
    let commandId: String
    let status: CommandStatus
    let response: String
    let executionTime: Double
    let data: [String: AnyCodable]?
    
    enum CommandStatus: String, Codable {
        case success
        case error
        case pending
    }
    
    enum CodingKeys: String, CodingKey {
        case commandId = "command_id"
        case status, response
        case executionTime = "execution_time"
        case data
    }
}

// MARK: - Performance Models

struct PerformanceMetrics: Codable {
    let cpu: CPUMetrics
    let memory: MemoryMetrics
    let disk: DiskMetrics
    let network: NetworkMetrics
}

struct CPUMetrics: Codable {
    let usage: Double
    let cores: Int
    let temperature: Double?
}

struct MemoryMetrics: Codable {
    let total: Double      // GB
    let used: Double       // GB
    let free: Double       // GB
    let percentage: Double
}

struct DiskMetrics: Codable {
    let total: Double      // GB
    let used: Double       // GB
    let free: Double       // GB
    let percentage: Double
}

struct NetworkMetrics: Codable {
    let rx: Int64  // bytes received
    let tx: Int64  // bytes transmitted
}

// MARK: - API Response Models

struct APIResponse<T: Codable>: Codable {
    let success: Bool
    let data: T?
    let error: String?
    let message: String?
    let timestamp: Date
}

struct HealthCheck: Codable {
    let status: HealthStatus
    let uptime: Int64
    let version: String
    let services: ServiceStatus
    let metrics: PerformanceMetrics
    
    enum HealthStatus: String, Codable {
        case healthy
        case degraded
        case unhealthy
    }
}

struct ServiceStatus: Codable {
    let python: Bool
    let typescript: Bool
    let redis: Bool?
    let database: Bool
}

// MARK: - Session Models

struct Session: Codable, Identifiable {
    let id: String
    let userId: String
    let startTime: Date
    let lastActivity: Date
    let metadata: [String: AnyCodable]
    
    enum CodingKeys: String, CodingKey {
        case id
        case userId = "user_id"
        case startTime = "start_time"
        case lastActivity = "last_activity"
        case metadata
    }
}

// MARK: - AI Provider Models

struct AIProvider: Codable, Identifiable {
    let id = UUID()
    let name: String
    let models: [String]
    let available: Bool
    let costPerToken: Double?
    let maxTokens: Int
    let supportsStreaming: Bool
    
    enum CodingKeys: String, CodingKey {
        case name, models, available
        case costPerToken = "cost_per_token"
        case maxTokens = "max_tokens"
        case supportsStreaming = "supports_streaming"
    }
}

struct AIRequest: Codable {
    let prompt: String
    let provider: String?
    let model: String?
    let temperature: Double?
    let maxTokens: Int?
    let stream: Bool?
    let sessionId: String?
    
    enum CodingKeys: String, CodingKey {
        case prompt, provider, model, temperature, stream
        case maxTokens = "max_tokens"
        case sessionId = "session_id"
    }
}

struct AIResponse: Codable {
    let text: String
    let provider: String
    let model: String
    let tokensUsed: Int
    let cost: Double
    let latency: Double
    let cached: Bool
    
    enum CodingKeys: String, CodingKey {
        case text, provider, model, cost, latency, cached
        case tokensUsed = "tokens_used"
    }
}

// MARK: - Memory Models

struct Memory: Codable, Identifiable {
    let id: String
    let content: String
    let type: MemoryType
    let embedding: [Double]?
    let metadata: [String: AnyCodable]
    let createdAt: Date
    let relevance: Double?
    
    enum MemoryType: String, Codable {
        case user
        case conversation
        case fact
        case task
    }
    
    enum CodingKeys: String, CodingKey {
        case id, content, type, embedding, metadata, relevance
        case createdAt = "created_at"
    }
}

// MARK: - WebSocket Message Models

enum WSMessageType: String, Codable {
    case voiceCommand = "voice_command"
    case systemStatus = "system_status"
    case notification
    case error
    case performanceUpdate = "performance_update"
    case chatMessage = "chat_message"
}

struct WSMessage<T: Codable>: Codable {
    let type: WSMessageType
    let data: T
    let timestamp: Date
    let id: String
}

// MARK: - Helper: AnyCodable for dynamic JSON

struct AnyCodable: Codable {
    let value: Any
    
    init(_ value: Any) {
        self.value = value
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported type"
            )
        }
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        switch value {
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [Any]:
            try container.encode(array.map { AnyCodable($0) })
        case let dict as [String: Any]:
            try container.encode(dict.mapValues { AnyCodable($0) })
        default:
            throw EncodingError.invalidValue(
                value,
                EncodingError.Context(
                    codingPath: container.codingPath,
                    debugDescription: "Unsupported type"
                )
            )
        }
    }
}

// MARK: - App Configuration

struct AppConfig: Codable {
    let pythonAPI: URL
    let typescriptAPI: URL
    let websocketURL: URL
    let apiKey: String?
    let sessionTimeout: Int
    
    static let `default` = AppConfig(
        pythonAPI: URL(string: "http://127.0.0.1:8000")!,
        typescriptAPI: URL(string: "http://127.0.0.1:3001")!,
        websocketURL: URL(string: "ws://127.0.0.1:3001")!,
        apiKey: nil,
        sessionTimeout: 3600
    )
    
    enum CodingKeys: String, CodingKey {
        case pythonAPI = "python_api"
        case typescriptAPI = "typescript_api"
        case websocketURL = "websocket_url"
        case apiKey = "api_key"
        case sessionTimeout = "session_timeout"
    }
}
