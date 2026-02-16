//
//  AetherApp.swift
//  Aether AI for macOS
//
//  Native macOS application with SwiftUI
//  Optimized for Apple Silicon (M1/M2/M3)
//

import SwiftUI

@main
struct AetherApp: App {
    @StateObject private var apiClient = AetherAPIClient()
    @StateObject private var appState = AppState()
    
    var body: some Scene {
        // Main window
        WindowGroup {
            ContentView()
                .environmentObject(apiClient)
                .environmentObject(appState)
                .frame(minWidth: 900, minHeight: 600)
                .onAppear {
                    // Connect to backends on launch
                    apiClient.connectWebSocket()
                    
                    Task {
                        await loadInitialData()
                    }
                }
        }
        .windowStyle(.hiddenTitleBar)
        .windowToolbarStyle(.unified(showsTitle: false))
        .commands {
            // Custom menu commands
            AetherCommands()
        }
        
        // Settings window
        Settings {
            SettingsView()
                .environmentObject(apiClient)
                .environmentObject(appState)
        }
        
        // Menu bar extra (status bar icon)
        MenuBarExtra("Aether AI", systemImage: "brain.head.profile") {
            MenuBarView()
                .environmentObject(apiClient)
                .environmentObject(appState)
        }
        .menuBarExtraStyle(.window)
    }
    
    private func loadInitialData() async {
        do {
            // Get health check
            let health = try await apiClient.getHealthCheck()
            await MainActor.run {
                appState.systemHealth = health
            }
            
            // Get AI providers
            let providers = try await apiClient.getAIProviders()
            await MainActor.run {
                appState.aiProviders = providers
            }
            
            // Get performance metrics
            let metrics = try await apiClient.getPerformanceMetrics()
            await MainActor.run {
                appState.performanceMetrics = metrics
            }
            
        } catch {
            print("❌ Error loading initial data: \(error)")
        }
    }
}

// MARK: - App State

class AppState: ObservableObject {
    @Published var systemHealth: HealthCheck?
    @Published var aiProviders: [AIProvider] = []
    @Published var performanceMetrics: PerformanceMetrics?
    @Published var selectedTab: Tab = .dashboard
    @Published var isVoiceListening: Bool = false
    @Published var currentSession: String = UUID().uuidString
    
    enum Tab: String, CaseIterable {
        case dashboard = "Dashboard"
        case chat = "Chat"
        case voice = "Voice"
        case performance = "Performance"
        case memory = "Memory"
        case settings = "Settings"
        
        var icon: String {
            switch self {
            case .dashboard: return "square.grid.2x2"
            case .chat: return "message.fill"
            case .voice: return "waveform"
            case .performance: return "chart.xyaxis.line"
            case .memory: return "brain"
            case .settings: return "gearshape.fill"
            }
        }
    }
}

// MARK: - Content View

struct ContentView: View {
    @EnvironmentObject var apiClient: AetherAPIClient
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        NavigationSplitView {
            // Sidebar
            SidebarView()
        } detail: {
            // Main content
            Group {
                switch appState.selectedTab {
                case .dashboard:
                    DashboardView()
                case .chat:
                    ChatView()
                case .voice:
                    VoiceView()
                case .performance:
                    PerformanceView()
                case .memory:
                    MemoryView()
                case .settings:
                    SettingsView()
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
    }
}

// MARK: - Sidebar

struct SidebarView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var apiClient: AetherAPIClient
    
    var body: some View {
        List(AppState.Tab.allCases, id: \.self, selection: $appState.selectedTab) { tab in
            Label(tab.rawValue, systemImage: tab.icon)
                .tag(tab)
        }
        .listStyle(.sidebar)
        .navigationTitle("Aether AI")
        .toolbar {
            ToolbarItem {
                HStack(spacing: 8) {
                    // Connection status
                    Circle()
                        .fill(apiClient.isConnected ? Color.green : Color.red)
                        .frame(width: 8, height: 8)
                    
                    Text(apiClient.isConnected ? "Connected" : "Disconnected")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

// MARK: - Dashboard View

struct DashboardView: View {
    @EnvironmentObject var appState: AppState
    @EnvironmentObject var apiClient: AetherAPIClient
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Header
                VStack(alignment: .leading, spacing: 8) {
                    Text("Dashboard")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    
                    Text("System Overview")
                        .font(.headline)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
                
                // Stats cards
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 16) {
                    if let metrics = appState.performanceMetrics {
                        StatCard(
                            title: "CPU Usage",
                            value: String(format: "%.1f%%", metrics.cpu.usage),
                            icon: "cpu",
                            color: .blue
                        )
                        
                        StatCard(
                            title: "Memory",
                            value: String(format: "%.1f GB", metrics.memory.used),
                            subtitle: String(format: "of %.0f GB", metrics.memory.total),
                            icon: "memorychip",
                            color: .purple
                        )
                        
                        StatCard(
                            title: "Disk",
                            value: String(format: "%.0f GB", metrics.disk.free),
                            subtitle: "free",
                            icon: "externaldrive",
                            color: .green
                        )
                    }
                }
                .padding(.horizontal)
                
                // Quick actions
                VStack(alignment: .leading, spacing: 12) {
                    Text("Quick Actions")
                        .font(.headline)
                        .padding(.horizontal)
                    
                    LazyVGrid(columns: [
                        GridItem(.flexible()),
                        GridItem(.flexible())
                    ], spacing: 12) {
                        QuickActionButton(
                            title: "Start Voice",
                            icon: "mic.fill",
                            color: .blue
                        ) {
                            appState.isVoiceListening.toggle()
                        }
                        
                        QuickActionButton(
                            title: "New Chat",
                            icon: "message.fill",
                            color: .green
                        ) {
                            appState.selectedTab = .chat
                        }
                        
                        QuickActionButton(
                            title: "Performance",
                            icon: "chart.bar.fill",
                            color: .orange
                        ) {
                            appState.selectedTab = .performance
                        }
                        
                        QuickActionButton(
                            title: "Settings",
                            icon: "gearshape.fill",
                            color: .gray
                        ) {
                            appState.selectedTab = .settings
                        }
                    }
                    .padding(.horizontal)
                }
                
                Spacer()
            }
            .padding()
        }
    }
}

// MARK: - Helper Views

struct StatCard: View {
    let title: String
    let value: String
    var subtitle: String? = nil
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                
                Spacer()
            }
            
            VStack(alignment: .leading, spacing: 4) {
                Text(value)
                    .font(.title)
                    .fontWeight(.bold)
                
                if let subtitle = subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(NSColor.controlBackgroundColor))
        )
    }
}

struct QuickActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                    .font(.title3)
                
                Text(title)
                    .font(.headline)
                
                Spacer()
            }
            .padding()
            .frame(maxWidth: .infinity)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(color.opacity(0.2))
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Placeholder Views

struct ChatView: View {
    var body: some View {
        Text("Chat View Coming Soon")
            .font(.title)
    }
}

struct VoiceView: View {
    var body: some View {
        Text("Voice Control View Coming Soon")
            .font(.title)
    }
}

struct PerformanceView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        if let metrics = appState.performanceMetrics {
            ScrollView {
                VStack(spacing: 20) {
                    Text("Performance Metrics")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                    
                    // Detailed metrics
                    VStack(alignment: .leading, spacing: 12) {
                        Text("CPU: \(String(format: "%.1f%%", metrics.cpu.usage))")
                        Text("Memory: \(String(format: "%.1f GB / %.0f GB", metrics.memory.used, metrics.memory.total))")
                        Text("Disk: \(String(format: "%.0f GB free", metrics.disk.free))")
                    }
                    .font(.headline)
                }
                .padding()
            }
        } else {
            Text("Loading performance metrics...")
        }
    }
}

struct MemoryView: View {
    var body: some View {
        Text("Memory View Coming Soon")
            .font(.title)
    }
}

struct SettingsView: View {
    var body: some View {
        Form {
            Section("General") {
                Text("Settings Coming Soon")
            }
        }
        .padding()
    }
}

struct MenuBarView: View {
    @EnvironmentObject var apiClient: AetherAPIClient
    
    var body: some View {
        VStack {
            Text("Aether AI")
                .font(.headline)
            
            Divider()
            
            Button("Show Main Window") {
                NSApp.activate(ignoringOtherApps: true)
            }
            
            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
        }
        .padding()
    }
}

// MARK: - Commands

struct AetherCommands: Commands {
    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Chat Session") {
                // Action
            }
            .keyboardShortcut("n", modifiers: .command)
        }
    }
}
