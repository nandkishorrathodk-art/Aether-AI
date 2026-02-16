//
//  AetherAPIClient.swift
//  Aether AI - API Client
//
//  High-performance API client for Python and TypeScript backends
//

import Foundation
import Alamofire
import Starscream
import SwiftyJSON

@MainActor
class AetherAPIClient: ObservableObject {
    // MARK: - Properties
    
    @Published var isConnected: Bool = false
    @Published var performanceMetrics: PerformanceMetrics?
    @Published var lastError: String?
    
    private let config: AppConfig
    private var webSocket: WebSocket?
    private let session: Session
    
    private var messageHandlers: [WSMessageType: (JSON) -> Void] = [:]
    
    // MARK: - Initialization
    
    init(config: AppConfig = .default) {
        self.config = config
        self.session = Session(configuration: .default)
    }
    
    // MARK: - HTTP Requests
    
    /// Execute voice command
    func executeVoiceCommand(
        text: String,
        sessionId: String = UUID().uuidString
    ) async throws -> VoiceCommandResult {
        let parameters: [String: Any] = [
            "text": text,
            "session_id": sessionId
        ]
        
        let response = try await request(
            url: config.pythonAPI.appendingPathComponent("/api/v1/voice-commands/execute"),
            method: .post,
            parameters: parameters
        )
        
        return try JSONDecoder().decode(VoiceCommandResult.self, from: response)
    }
    
    /// Get performance metrics from TypeScript backend
    func getPerformanceMetrics() async throws -> PerformanceMetrics {
        let response = try await request(
            url: config.typescriptAPI.appendingPathComponent("/api/performance"),
            method: .get
        )
        
        let apiResponse = try JSONDecoder().decode(
            APIResponse<PerformanceMetrics>.self,
            from: response
        )
        
        guard let metrics = apiResponse.data else {
            throw APIError.noData
        }
        
        DispatchQueue.main.async {
            self.performanceMetrics = metrics
        }
        
        return metrics
    }
    
    /// Get health check
    func getHealthCheck() async throws -> HealthCheck {
        let response = try await request(
            url: config.typescriptAPI.appendingPathComponent("/health"),
            method: .get
        )
        
        return try JSONDecoder().decode(HealthCheck.self, from: response)
    }
    
    /// Get AI providers
    func getAIProviders() async throws -> [AIProvider] {
        let response = try await request(
            url: config.pythonAPI.appendingPathComponent("/api/v1/chat/providers"),
            method: .get
        )
        
        let json = try JSON(data: response)
        let providersData = try json["providers"].rawData()
        
        let decoder = JSONDecoder()
        let providers = try decoder.decode([String: AIProvider].self, from: providersData)
        
        return Array(providers.values)
    }
    
    /// Send chat message
    func sendChatMessage(
        prompt: String,
        provider: String? = nil,
        model: String? = nil,
        sessionId: String = UUID().uuidString
    ) async throws -> AIResponse {
        let request = AIRequest(
            prompt: prompt,
            provider: provider,
            model: model,
            temperature: nil,
            maxTokens: nil,
            stream: false,
            sessionId: sessionId
        )
        
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let requestData = try encoder.encode(request)
        let parameters = try JSON(data: requestData).dictionaryObject
        
        let response = try await self.request(
            url: config.pythonAPI.appendingPathComponent("/api/v1/chat"),
            method: .post,
            parameters: parameters
        )
        
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(AIResponse.self, from: response)
    }
    
    // MARK: - WebSocket
    
    /// Connect to WebSocket
    func connectWebSocket() {
        var request = URLRequest(url: config.websocketURL)
        request.timeoutInterval = 5
        
        webSocket = WebSocket(request: request)
        webSocket?.delegate = self
        webSocket?.connect()
    }
    
    /// Disconnect WebSocket
    func disconnectWebSocket() {
        webSocket?.disconnect()
        isConnected = false
    }
    
    /// Send WebSocket message
    func sendWebSocketMessage<T: Codable>(type: WSMessageType, data: T) throws {
        let message = WSMessage(
            type: type,
            data: data,
            timestamp: Date(),
            id: UUID().uuidString
        )
        
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        let messageData = try encoder.encode(message)
        
        webSocket?.write(data: messageData)
    }
    
    /// Register message handler
    func onMessage(type: WSMessageType, handler: @escaping (JSON) -> Void) {
        messageHandlers[type] = handler
    }
    
    // MARK: - Private Helpers
    
    private func request(
        url: URL,
        method: HTTPMethod,
        parameters: [String: Any]? = nil
    ) async throws -> Data {
        return try await withCheckedThrowingContinuation { continuation in
            AF.request(
                url,
                method: method,
                parameters: parameters,
                encoding: JSONEncoding.default,
                headers: [
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                ]
            )
            .validate()
            .responseData { response in
                switch response.result {
                case .success(let data):
                    continuation.resume(returning: data)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}

// MARK: - WebSocket Delegate

extension AetherAPIClient: WebSocketDelegate {
    nonisolated func didReceive(event: WebSocketEvent, client: WebSocket) {
        Task { @MainActor in
            switch event {
            case .connected(_):
                self.isConnected = true
                print("✅ WebSocket connected")
                
            case .disconnected(let reason, let code):
                self.isConnected = false
                print("❌ WebSocket disconnected: \(reason) (code: \(code))")
                
            case .text(let string):
                self.handleWebSocketMessage(string)
                
            case .binary(let data):
                if let string = String(data: data, encoding: .utf8) {
                    self.handleWebSocketMessage(string)
                }
                
            case .error(let error):
                self.lastError = error?.localizedDescription
                print("❌ WebSocket error: \(String(describing: error))")
                
            case .cancelled:
                self.isConnected = false
                print("⚠️ WebSocket cancelled")
                
            default:
                break
            }
        }
    }
    
    private func handleWebSocketMessage(_ message: String) {
        guard let data = message.data(using: .utf8),
              let json = try? JSON(data: data) else {
            return
        }
        
        guard let typeString = json["type"].string,
              let type = WSMessageType(rawValue: typeString) else {
            return
        }
        
        let messageData = json["data"]
        
        // Call registered handler
        messageHandlers[type]?(messageData)
        
        // Handle specific message types
        switch type {
        case .performanceUpdate:
            if let metricsData = try? messageData.rawData(),
               let metrics = try? JSONDecoder().decode(PerformanceMetrics.self, from: metricsData) {
                self.performanceMetrics = metrics
            }
            
        case .error:
            if let errorMessage = messageData["message"].string {
                self.lastError = errorMessage
            }
            
        default:
            break
        }
    }
}

// MARK: - API Errors

enum APIError: Error, LocalizedError {
    case noData
    case invalidResponse
    case serverError(String)
    
    var errorDescription: String? {
        switch self {
        case .noData:
            return "No data received from server"
        case .invalidResponse:
            return "Invalid response from server"
        case .serverError(let message):
            return "Server error: \(message)"
        }
    }
}
