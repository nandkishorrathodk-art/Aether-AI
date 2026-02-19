from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set, Optional
import json
import asyncio
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Ultra-fast WebSocket connection manager
    Features:
    - Room-based subscriptions
    - Broadcast to specific rooms
    - Individual messaging
    - Connection tracking
    - Auto-cleanup
    """
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_rooms: Dict[str, Set[str]] = {}
        self.room_users: Dict[str, Set[str]] = {}
        logger.info("WebSocket ConnectionManager initialized")
    
    async def connect(self, websocket: WebSocket, user_id: str):
        """Connect new WebSocket client"""
        await websocket.accept()
        self.active_connections[user_id] = websocket
        self.user_rooms[user_id] = set()
        logger.info(f"WebSocket connected: {user_id}")
        
        await self.send_personal_message(
            user_id,
            {
                "type": "connection",
                "status": "connected",
                "user_id": user_id,
                "timestamp": datetime.now().isoformat()
            }
        )
    
    def disconnect(self, user_id: str):
        """Disconnect WebSocket client"""
        if user_id in self.active_connections:
            # Remove from all rooms
            rooms = self.user_rooms.get(user_id, set()).copy()
            for room in rooms:
                self.leave_room(user_id, room)
            
            # Remove connection
            del self.active_connections[user_id]
            if user_id in self.user_rooms:
                del self.user_rooms[user_id]
            
            logger.info(f"WebSocket disconnected: {user_id}")
    
    async def send_personal_message(self, user_id: str, message: dict):
        """Send message to specific user"""
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to {user_id}: {e}")
                self.disconnect(user_id)
    
    async def broadcast(self, message: dict, exclude: Optional[Set[str]] = None):
        """Broadcast message to all connected users"""
        exclude = exclude or set()
        disconnected = []
        
        for user_id, connection in self.active_connections.items():
            if user_id not in exclude:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Broadcast failed for {user_id}: {e}")
                    disconnected.append(user_id)
        
        # Clean up disconnected
        for user_id in disconnected:
            self.disconnect(user_id)
    
    def join_room(self, user_id: str, room: str):
        """Add user to room"""
        if user_id not in self.user_rooms:
            self.user_rooms[user_id] = set()
        self.user_rooms[user_id].add(room)
        
        if room not in self.room_users:
            self.room_users[room] = set()
        self.room_users[room].add(user_id)
        
        logger.debug(f"{user_id} joined room: {room}")
    
    def leave_room(self, user_id: str, room: str):
        """Remove user from room"""
        if user_id in self.user_rooms:
            self.user_rooms[user_id].discard(room)
        
        if room in self.room_users:
            self.room_users[room].discard(user_id)
            # Clean up empty rooms
            if not self.room_users[room]:
                del self.room_users[room]
        
        logger.debug(f"{user_id} left room: {room}")
    
    async def broadcast_to_room(self, room: str, message: dict):
        """Broadcast message to all users in room"""
        if room not in self.room_users:
            return
        
        disconnected = []
        for user_id in self.room_users[room]:
            if user_id in self.active_connections:
                try:
                    await self.active_connections[user_id].send_json(message)
                except Exception as e:
                    logger.error(f"Room broadcast failed for {user_id}: {e}")
                    disconnected.append(user_id)
        
        # Clean up disconnected
        for user_id in disconnected:
            self.disconnect(user_id)
    
    def get_room_users(self, room: str) -> Set[str]:
        """Get all users in room"""
        return self.room_users.get(room, set()).copy()
    
    def get_user_rooms(self, user_id: str) -> Set[str]:
        """Get all rooms user is in"""
        return self.user_rooms.get(user_id, set()).copy()
    
    def get_stats(self) -> dict:
        """Get connection statistics"""
        return {
            "total_connections": len(self.active_connections),
            "total_rooms": len(self.room_users),
            "users_by_room": {
                room: len(users) for room, users in self.room_users.items()
            }
        }


# Global connection manager
manager = ConnectionManager()


async def handle_websocket_message(user_id: str, message: dict):
    """
    Handle incoming WebSocket messages
    Message types:
    - join_room: Subscribe to room
    - leave_room: Unsubscribe from room
    - message: Send message to room
    - broadcast: Send to all users
    """
    msg_type = message.get("type")
    
    if msg_type == "join_room":
        room = message.get("room")
        if room:
            manager.join_room(user_id, room)
            await manager.send_personal_message(
                user_id,
                {"type": "joined_room", "room": room}
            )
            # Notify room
            await manager.broadcast_to_room(
                room,
                {
                    "type": "user_joined",
                    "user_id": user_id,
                    "room": room,
                    "timestamp": datetime.now().isoformat()
                }
            )
    
    elif msg_type == "leave_room":
        room = message.get("room")
        if room:
            manager.leave_room(user_id, room)
            await manager.send_personal_message(
                user_id,
                {"type": "left_room", "room": room}
            )
            # Notify room
            await manager.broadcast_to_room(
                room,
                {
                    "type": "user_left",
                    "user_id": user_id,
                    "room": room,
                    "timestamp": datetime.now().isoformat()
                }
            )
    
    elif msg_type == "message":
        room = message.get("room")
        content = message.get("content")
        if room and content:
            await manager.broadcast_to_room(
                room,
                {
                    "type": "message",
                    "user_id": user_id,
                    "room": room,
                    "content": content,
                    "timestamp": datetime.now().isoformat()
                }
            )
    
    elif msg_type == "broadcast":
        content = message.get("content")
        if content:
            await manager.broadcast(
                {
                    "type": "broadcast",
                    "user_id": user_id,
                    "content": content,
                    "timestamp": datetime.now().isoformat()
                },
                exclude={user_id}
            )
    
    elif msg_type == "ping":
        await manager.send_personal_message(
            user_id,
            {"type": "pong", "timestamp": datetime.now().isoformat()}
        )
    
    else:
        await manager.send_personal_message(
            user_id,
            {"type": "error", "message": f"Unknown message type: {msg_type}"}
        )


async def websocket_endpoint(websocket: WebSocket, user_id: str = "anonymous"):
    """
    Main WebSocket endpoint handler
    """
    await manager.connect(websocket, user_id)
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle message
            await handle_websocket_message(user_id, message)
    
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        logger.info(f"WebSocket client disconnected: {user_id}")
    
    except Exception as e:
        logger.error(f"WebSocket error for {user_id}: {e}")
        manager.disconnect(user_id)


# Real-time event emitters for Aether AI

async def emit_scan_progress(session_id: str, progress: dict):
    """Emit autonomous scan progress to WebSocket clients"""
    await manager.broadcast_to_room(
        f"scan:{session_id}",
        {
            "type": "scan_progress",
            "session_id": session_id,
            "progress": progress,
            "timestamp": datetime.now().isoformat()
        }
    )


async def emit_vulnerability_found(session_id: str, vulnerability: dict):
    """Emit newly found vulnerability"""
    await manager.broadcast_to_room(
        f"scan:{session_id}",
        {
            "type": "vulnerability_found",
            "session_id": session_id,
            "vulnerability": vulnerability,
            "timestamp": datetime.now().isoformat()
        }
    )


async def emit_llm_response_stream(user_id: str, chunk: str):
    """Stream LLM response chunks"""
    await manager.send_personal_message(
        user_id,
        {
            "type": "llm_chunk",
            "chunk": chunk,
            "timestamp": datetime.now().isoformat()
        }
    )


async def emit_voice_transcription(user_id: str, text: str, is_final: bool = False):
    """Emit voice transcription updates"""
    await manager.send_personal_message(
        user_id,
        {
            "type": "voice_transcription",
            "text": text,
            "is_final": is_final,
            "timestamp": datetime.now().isoformat()
        }
    )


async def emit_system_notification(message: str, severity: str = "info"):
    """Broadcast system notification to all users"""
    await manager.broadcast(
        {
            "type": "system_notification",
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
    )
