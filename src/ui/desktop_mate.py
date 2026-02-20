import sys
import asyncio
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QWidget, QMenu, QSystemTrayIcon
)
from PyQt6.QtCore import Qt, QPoint, QTimer, QSize, pyqtSignal, QThread
from PyQt6.QtGui import QPainter, QColor, QPen, QAction, QIcon, QPixmap, QPainterPath
import requests
import logging
from src.ui.voice_handler import VoiceHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VoiceThread(QThread):
    """Thread for voice recording to avoid blocking UI"""
    finished = pyqtSignal(str, str)
    
    def __init__(self, voice_handler):
        super().__init__()
        self.voice_handler = voice_handler
    
    def run(self):
        """Record and process voice"""
        import time
        
        # Record for 5 seconds
        self.voice_handler.start_recording()
        time.sleep(5)
        audio_data = self.voice_handler.stop_recording()
        
        if audio_data is not None:
            # Transcribe
            user_text = self.voice_handler.transcribe(audio_data)
            if user_text:
                # Get AI response
                ai_text = self.voice_handler.get_response(user_text)
                self.finished.emit(user_text, ai_text)
            else:
                self.finished.emit("", "Sorry, I didn't catch that.")


class AetherDesktopMate(QWidget):
    """
    Desktop Mate for Aether AI - Floating AI character
    Features:
    - Transparent floating window
    - Draggable character
    - Click to talk
    - Right-click menu
    - Voice integration
    - Animations (idle, listening, speaking)
    """
    
    status_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.backend_url = "http://localhost:8000"
        self.character_size = 150  # Original small size
        self.is_listening = False
        self.is_speaking = False
        self.is_dragging = False
        self.drag_position = QPoint()
        self.animation_frame = 0
        self.current_state = "idle"
        
        self.voice_handler = VoiceHandler(self.backend_url)
        self.voice_thread = None
        
        self.init_ui()
        self.setup_animation_timer()
        self.setup_tray_icon()
        
    def init_ui(self):
        """Initialize the UI"""
        self.setWindowTitle("Aether Desktop Mate")
        
        # Simple window flags - just frameless and on top
        self.setWindowFlags(
            Qt.WindowType.Window |  # Normal window
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        
        # Set size and position (BOTTOM-RIGHT corner)
        screen = QApplication.primaryScreen().geometry()
        self.setFixedSize(self.character_size, self.character_size)
        
        # Bottom-right corner
        x_pos = screen.width() - self.character_size - 50
        y_pos = screen.height() - self.character_size - 100
        self.move(x_pos, y_pos)
        
        print(f"\n🤖 Desktop Mate Window Created!")
        print(f"   Screen Size: {screen.width()}x{screen.height()}")
        print(f"   Character Size: {self.character_size}x{self.character_size}")
        print(f"   Position: X={x_pos}, Y={y_pos}")
        print(f"   Window Visible: {self.isVisible()}")
        print(f"   Always On Top: {self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint}")
        
        logger.info("🤖 Aether Desktop Mate initialized")
    
    def setup_animation_timer(self):
        """Setup animation timer for character movement"""
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.update_animation)
        self.animation_timer.start(100)  # 10 FPS
    
    def setup_tray_icon(self):
        """Setup system tray icon"""
        self.tray_icon = QSystemTrayIcon(self)
        
        # Create icon
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QColor(0, 255, 255))
        painter.drawEllipse(4, 4, 24, 24)
        painter.end()
        
        self.tray_icon.setIcon(QIcon(pixmap))
        self.tray_icon.setToolTip("Aether Desktop Mate")
        
        # Tray menu
        tray_menu = QMenu()
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        hide_action = QAction("Hide", self)
        hide_action.triggered.connect(self.hide)
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(QApplication.quit)
        
        tray_menu.addAction(show_action)
        tray_menu.addAction(hide_action)
        tray_menu.addSeparator()
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
    
    def update_animation(self):
        """Update animation frame"""
        self.animation_frame = (self.animation_frame + 1) % 20
        self.update()
    
    def paintEvent(self, event):
        """Paint the character"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw character based on state
        if self.current_state == "listening":
            self.draw_listening(painter)
        elif self.current_state == "speaking":
            self.draw_speaking(painter)
        elif self.current_state == "dragged":
            self.draw_dragged(painter)
        else:
            self.draw_idle(painter)
    
    def draw_idle(self, painter):
        """Draw idle state - floating orb with glow"""
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = 50  # Small orb
        
        # Glow effect
        glow_radius = radius + 10 + (self.animation_frame % 10)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 255, 255, 30))
        painter.drawEllipse(
            center_x - glow_radius,
            center_y - glow_radius,
            glow_radius * 2,
            glow_radius * 2
        )
        
        # Main orb
        painter.setBrush(QColor(0, 200, 255))
        painter.drawEllipse(
            center_x - radius,
            center_y - radius,
            radius * 2,
            radius * 2
        )
        
        # Eyes
        eye_y = center_y - 10
        painter.setBrush(QColor(255, 255, 255))
        painter.drawEllipse(center_x - 20, eye_y, 10, 10)
        painter.drawEllipse(center_x + 10, eye_y, 10, 10)
        
        # Pupils (blink animation)
        if self.animation_frame % 20 != 0:
            painter.setBrush(QColor(0, 0, 0))
            painter.drawEllipse(center_x - 17, eye_y + 3, 4, 4)
            painter.drawEllipse(center_x + 13, eye_y + 3, 4, 4)
    
    def draw_listening(self, painter):
        """Draw listening state - pulsing red"""
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = 50 + (self.animation_frame % 10)
        
        # Pulsing red glow
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(255, 0, 0, 50))
        painter.drawEllipse(
            center_x - radius - 10,
            center_y - radius - 10,
            (radius + 10) * 2,
            (radius + 10) * 2
        )
        
        # Main orb
        painter.setBrush(QColor(255, 50, 50))
        painter.drawEllipse(
            center_x - radius,
            center_y - radius,
            radius * 2,
            radius * 2
        )
        
        # Microphone icon
        painter.setPen(QPen(QColor(255, 255, 255), 3))
        painter.drawEllipse(center_x - 10, center_y - 15, 20, 25)
        painter.drawLine(center_x, center_y + 15, center_x, center_y + 25)
    
    def draw_speaking(self, painter):
        """Draw speaking state - purple with sound waves"""
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = 50
        
        # Sound waves
        wave_offset = self.animation_frame * 5
        painter.setPen(QPen(QColor(200, 0, 255, 100), 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for i in range(3):
            wave_radius = radius + 15 + (i * 10) + (wave_offset % 30)
            painter.drawEllipse(
                center_x - wave_radius,
                center_y - wave_radius,
                wave_radius * 2,
                wave_radius * 2
            )
        
        # Main orb
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(200, 0, 255))
        painter.drawEllipse(
            center_x - radius,
            center_y - radius,
            radius * 2,
            radius * 2
        )
        
        # Mouth animation
        mouth_width = 20 + (self.animation_frame % 10)
        painter.setBrush(QColor(255, 255, 255))
        painter.drawEllipse(center_x - mouth_width//2, center_y + 5, mouth_width, 15)
    
    def draw_dragged(self, painter):
        """Draw dragged state - tilted"""
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = 50
        
        # Slightly transparent
        painter.setOpacity(0.7)
        
        # Main orb (tilted effect with gradient)
        painter.setBrush(QColor(0, 255, 200))
        painter.drawEllipse(
            center_x - radius,
            center_y - radius,
            radius * 2,
            radius * 2
        )
        
        # Motion lines
        painter.setPen(QPen(QColor(0, 255, 200, 100), 3))
        painter.drawLine(center_x - 60, center_y - 20, center_x - 45, center_y - 15)
        painter.drawLine(center_x - 60, center_y, center_x - 45, center_y)
        painter.drawLine(center_x - 60, center_y + 20, center_x - 45, center_y + 15)
    
    def mousePressEvent(self, event):
        """Handle mouse press - start dragging or trigger action"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.is_dragging = True
            self.drag_position = event.globalPosition().toPoint() - self.pos()
            self.current_state = "dragged"
            event.accept()
    
    def mouseMoveEvent(self, event):
        """Handle mouse move - drag window"""
        if self.is_dragging:
            self.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()
    
    def mouseReleaseEvent(self, event):
        """Handle mouse release - stop dragging, trigger voice"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.is_dragging = False
            self.current_state = "idle"
            
            # Short drag = click action
            if (event.globalPosition().toPoint() - self.pos() - self.drag_position).manhattanLength() < 5:
                self.on_click()
            
            event.accept()
    
    def contextMenuEvent(self, event):
        """Show right-click menu"""
        menu = QMenu(self)
        
        # Actions
        talk_action = QAction("💬 Talk to Aether", self)
        talk_action.triggered.connect(self.on_click)
        
        listen_action = QAction("🎤 Voice Input", self)
        listen_action.triggered.connect(self.start_listening)
        
        menu.addAction(talk_action)
        menu.addAction(listen_action)
        menu.addSeparator()
        
        settings_action = QAction("⚙️ Settings", self)
        settings_action.triggered.connect(self.open_settings)
        
        hide_action = QAction("👻 Hide", self)
        hide_action.triggered.connect(self.hide)
        
        quit_action = QAction("❌ Quit", self)
        quit_action.triggered.connect(QApplication.quit)
        
        menu.addAction(settings_action)
        menu.addAction(hide_action)
        menu.addSeparator()
        menu.addAction(quit_action)
        
        menu.exec(event.globalPos())
    
    def on_click(self):
        """Handle click - greet and start conversation"""
        logger.info("🎯 Character clicked - starting conversation")
        
        # Use local TTS for instant feedback
        import pyttsx3
        try:
            engine = pyttsx3.init()
            engine.say("Yes sir! At your service!")
            engine.runAndWait()
        except:
            pass
        
        self.speak("Yes, sir? How may I assist you?")
    
    def start_listening(self):
        """Start voice listening"""
        logger.info("🎤 Starting voice input...")
        self.current_state = "listening"
        self.is_listening = True
        
        # Start voice thread
        self.voice_thread = VoiceThread(self.voice_handler)
        self.voice_thread.finished.connect(self.on_voice_complete)
        self.voice_thread.start()
    
    def stop_listening(self):
        """Stop voice listening"""
        self.is_listening = False
        self.current_state = "idle"
        logger.info("🛑 Voice input stopped")
    
    def on_voice_complete(self, user_text, ai_text):
        """Handle voice conversation completion"""
        logger.info(f"👤 User: {user_text}")
        logger.info(f"🤖 Aether: {ai_text}")
        
        self.is_listening = False
        self.speak(ai_text)
    
    def speak(self, text):
        """Speak text using Aether TTS"""
        logger.info(f"🔊 Speaking: {text}")
        self.current_state = "speaking"
        
        try:
            # Use voice handler to speak
            success = self.voice_handler.speak(text)
            
            if success:
                logger.info("✅ Speech complete")
            else:
                logger.error("❌ Speech failed")
            
            self.current_state = "idle"
        except Exception as e:
            logger.error(f"❌ Speak error: {e}")
            self.current_state = "idle"
    
    def open_settings(self):
        """Open settings (could open web UI)"""
        import webbrowser
        webbrowser.open("http://localhost:3000")


def main():
    """Run desktop mate"""
    import sys
    
    # Create QApplication if it doesn't exist
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    
    app.setQuitOnLastWindowClosed(False)
    
    logger.info("🤖 Desktop Mate - Initializing window...")
    
    mate = AetherDesktopMate()
    
    # Force visibility
    mate.setVisible(True)
    mate.show()
    mate.raise_()
    mate.repaint()
    
    # Process events
    app.processEvents()
    
    logger.info(f"✅ Desktop Mate visible: {mate.isVisible()}")
    logger.info(f"📍 Position: X={mate.x()}, Y={mate.y()}")
    logger.info("💡 Click orb to talk, Right-click for menu")
    
    # Run event loop (will block this thread)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
