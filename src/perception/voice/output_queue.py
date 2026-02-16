import queue
import threading
import logging
from typing import Optional, Callable
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class TTSRequest:
    """Represents a TTS request in the queue"""
    text: str
    priority: int = 5
    callback: Optional[Callable] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def __lt__(self, other):
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.timestamp < other.timestamp


class TTSOutputQueue:
    """Queue manager for handling concurrent TTS responses"""
    
    def __init__(self, tts_engine, max_queue_size: int = 50):
        self.tts_engine = tts_engine
        self.max_queue_size = max_queue_size
        
        self.queue = queue.PriorityQueue(maxsize=max_queue_size)
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None
        
        self.requests_processed = 0
        self.requests_failed = 0
        self.lock = threading.Lock()
        
        logger.info(f"TTSOutputQueue initialized with max size: {max_queue_size}")
    
    def start(self):
        """Start the queue worker thread"""
        if self.running:
            logger.warning("Queue already running")
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        logger.info("TTSOutputQueue worker started")
    
    def stop(self):
        """Stop the queue worker thread"""
        if not self.running:
            return
        
        self.running = False
        
        if self.worker_thread:
            self.worker_thread.join(timeout=5.0)
        
        logger.info("TTSOutputQueue worker stopped")
    
    def add(
        self,
        text: str,
        priority: int = 5,
        callback: Optional[Callable] = None,
        blocking: bool = False,
        timeout: Optional[float] = None
    ) -> bool:
        """Add a TTS request to the queue
        
        Args:
            text: Text to synthesize
            priority: Priority level (1=highest, 10=lowest)
            callback: Optional callback function called after synthesis
            blocking: If True, wait for queue space
            timeout: Timeout for blocking wait
        
        Returns:
            True if added successfully, False if queue is full
        """
        request = TTSRequest(text=text, priority=priority, callback=callback)
        
        try:
            self.queue.put(request, block=blocking, timeout=timeout)
            logger.debug(f"Added TTS request (priority={priority}): {text[:50]}...")
            return True
        except queue.Full:
            logger.warning(f"Queue full, dropping request: {text[:50]}...")
            return False
    
    def add_urgent(self, text: str, callback: Optional[Callable] = None) -> bool:
        """Add high-priority TTS request"""
        return self.add(text, priority=1, callback=callback, blocking=True, timeout=1.0)
    
    def add_normal(self, text: str, callback: Optional[Callable] = None) -> bool:
        """Add normal-priority TTS request"""
        return self.add(text, priority=5, callback=callback)
    
    def add_low(self, text: str, callback: Optional[Callable] = None) -> bool:
        """Add low-priority TTS request"""
        return self.add(text, priority=10, callback=callback)
    
    def _worker(self):
        """Worker thread that processes queue"""
        logger.info("Queue worker thread started")
        
        while self.running:
            try:
                request = self.queue.get(timeout=0.5)
                
                try:
                    logger.debug(f"Processing TTS request: {request.text[:50]}...")
                    
                    audio_data = self.tts_engine.speak(request.text, blocking=True)
                    
                    if request.callback:
                        try:
                            request.callback(audio_data)
                        except Exception as e:
                            logger.error(f"Callback error: {e}")
                    
                    with self.lock:
                        self.requests_processed += 1
                    
                    logger.debug(f"Successfully processed TTS request")
                
                except Exception as e:
                    logger.error(f"Failed to process TTS request: {e}")
                    with self.lock:
                        self.requests_failed += 1
                
                finally:
                    self.queue.task_done()
            
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker thread error: {e}")
        
        logger.info("Queue worker thread stopped")
    
    def clear(self):
        """Clear all pending requests"""
        try:
            while not self.queue.empty():
                self.queue.get_nowait()
                self.queue.task_done()
            logger.info("Queue cleared")
        except Exception as e:
            logger.error(f"Failed to clear queue: {e}")
    
    def get_stats(self) -> dict:
        """Get queue statistics"""
        with self.lock:
            return {
                'queue_size': self.queue.qsize(),
                'max_queue_size': self.max_queue_size,
                'requests_processed': self.requests_processed,
                'requests_failed': self.requests_failed,
                'running': self.running
            }
    
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return self.queue.empty()
    
    def is_full(self) -> bool:
        """Check if queue is full"""
        return self.queue.full()
    
    def wait_completion(self, timeout: Optional[float] = None):
        """Wait for all queued requests to complete"""
        try:
            self.queue.join()
            logger.info("All queued requests completed")
        except Exception as e:
            logger.error(f"Error waiting for completion: {e}")
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
