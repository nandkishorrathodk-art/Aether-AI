from fastapi import APIRouter, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import io
import logging
import numpy as np
from typing import Optional
import tempfile
import os

from ...perception.voice import (
    AudioInputHandler,
    SpeechToText,
    WakeWordDetector,
    SimpleWakeWordDetector,
    TextToSpeech,
    TTSConfig
)
from ...pipeline import get_pipeline, PipelineConfig
from ...config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/voice", tags=["voice"])

stt_instance: Optional[SpeechToText] = None
wake_word_detector: Optional[WakeWordDetector] = None
audio_handler: Optional[AudioInputHandler] = None
tts_instance: Optional[TextToSpeech] = None


def get_stt():
    global stt_instance
    if stt_instance is None:
        if settings.voice_provider == "openai" and settings.openai_api_key:
            stt_instance = SpeechToText(
                use_cloud=True,
                api_key=settings.openai_api_key
            )
            logger.info("Initialized cloud-based STT")
        else:
            stt_instance = SpeechToText(
                model_name="base",
                use_cloud=False,
                device="cpu"
            )
            logger.info("Initialized local STT with 'base' model")
    return stt_instance


def get_tts():
    global tts_instance
    if tts_instance is None:
        config = TTSConfig(
            provider=settings.tts_provider if hasattr(settings, 'tts_provider') else "pyttsx3",
            voice=settings.tts_voice if hasattr(settings, 'tts_voice') else "female",
            rate=settings.tts_rate if hasattr(settings, 'tts_rate') else 175,
            cache_enabled=True
        )
        
        api_key = None
        if config.provider == "openai" and hasattr(settings, 'openai_api_key'):
            api_key = settings.openai_api_key
        
        tts_instance = TextToSpeech(config=config, api_key=api_key)
        logger.info(f"Initialized TTS with provider: {config.provider}")
    return tts_instance


def get_wake_word_detector():
    global wake_word_detector
    if wake_word_detector is None:
        wake_word_detector = WakeWordDetector(
            wake_word=settings.wake_word,
            use_porcupine=False
        )
        logger.info(f"Initialized wake word detector for '{settings.wake_word}'")
    return wake_word_detector


def get_audio_handler():
    global audio_handler
    if audio_handler is None:
        audio_handler = AudioInputHandler()
        audio_handler.start_stream()
        logger.info("Initialized audio handler")
    return audio_handler


class TranscribeRequest(BaseModel):
    language: Optional[str] = None
    task: str = "transcribe"


class TranscribeResponse(BaseModel):
    text: str
    language: Optional[str]
    confidence: float
    source: str


class WakeWordStatusResponse(BaseModel):
    listening: bool
    wake_word: str


class AudioDeviceInfo(BaseModel):
    index: int
    name: str
    sample_rate: int
    channels: int


@router.post("/transcribe", response_model=TranscribeResponse)
async def transcribe_audio(
    audio: UploadFile = File(...),
    language: Optional[str] = None
):
    try:
        stt = get_stt()
        
        contents = await audio.read()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as temp_file:
            temp_file.write(contents)
            temp_path = temp_file.name
        
        try:
            result = stt.transcribe_audio(temp_path, language=language)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return TranscribeResponse(
            text=result["text"],
            language=result.get("language"),
            confidence=result.get("confidence", 0.0),
            source=result.get("source", "unknown")
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Transcription error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/transcribe-realtime", response_model=TranscribeResponse)
async def transcribe_realtime(
    duration: float = 5.0,
    language: Optional[str] = None
):
    try:
        if duration <= 0 or duration > 60:
            raise HTTPException(
                status_code=400,
                detail="Duration must be between 0 and 60 seconds"
            )
        
        stt = get_stt()
        handler = get_audio_handler()
        
        result = stt.transcribe_realtime(
            audio_handler=handler,
            duration_seconds=duration,
            language=language
        )
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return TranscribeResponse(
            text=result["text"],
            language=result.get("language"),
            confidence=result.get("confidence", 0.0),
            source=result.get("source", "unknown")
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Real-time transcription error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/transcribe-until-silence", response_model=TranscribeResponse)
async def transcribe_until_silence(
    max_duration: float = 30.0,
    silence_duration_ms: int = 1500,
    language: Optional[str] = None
):
    try:
        if max_duration <= 0 or max_duration > 120:
            raise HTTPException(
                status_code=400,
                detail="Max duration must be between 0 and 120 seconds"
            )
        
        stt = get_stt()
        handler = get_audio_handler()
        
        result = stt.transcribe_until_silence(
            audio_handler=handler,
            max_duration_seconds=max_duration,
            silence_duration_ms=silence_duration_ms,
            language=language
        )
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return TranscribeResponse(
            text=result["text"],
            language=result.get("language"),
            confidence=result.get("confidence", 0.0),
            source=result.get("source", "unknown")
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Silence-based transcription error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/wake-word/status", response_model=WakeWordStatusResponse)
async def get_wake_word_status():
    try:
        detector = get_wake_word_detector()
        return WakeWordStatusResponse(
            listening=detector.is_listening,
            wake_word=detector.wake_word
        )
    except Exception as e:
        logger.error(f"Wake word status error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/wake-word/start")
async def start_wake_word_detection(background_tasks: BackgroundTasks):
    try:
        detector = get_wake_word_detector()
        
        if detector.is_listening:
            return {"message": "Wake word detection already running"}
        
        def detect_wake_word():
            try:
                detector.listen_continuous(
                    on_wake_word=lambda: logger.info("Wake word detected in background"),
                    on_error=lambda e: logger.error(f"Wake word error: {e}")
                )
            except Exception as e:
                logger.error(f"Background wake word detection error: {e}")
        
        background_tasks.add_task(detect_wake_word)
        
        return {"message": "Wake word detection started"}
    except Exception as e:
        logger.error(f"Start wake word error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/wake-word/stop")
async def stop_wake_word_detection():
    try:
        detector = get_wake_word_detector()
        detector.stop_listening()
        return {"message": "Wake word detection stopped"}
    except Exception as e:
        logger.error(f"Stop wake word error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices", response_model=list[AudioDeviceInfo])
async def list_audio_devices():
    try:
        handler = AudioInputHandler()
        devices = handler.list_audio_devices()
        handler.cleanup()
        
        return [
            AudioDeviceInfo(
                index=device["index"],
                name=device["name"],
                sample_rate=device["sample_rate"],
                channels=device["channels"]
            )
            for device in devices
        ]
    except Exception as e:
        logger.error(f"List devices error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/models")
async def list_stt_models():
    try:
        stt = SpeechToText(use_cloud=False, model_name="base")
        models = stt.get_available_models()
        stt.cleanup()
        
        return {
            "models": models,
            "current": "base" if not settings.voice_provider == "openai" else "whisper-1"
        }
    except Exception as e:
        logger.error(f"List models error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/languages")
async def list_supported_languages():
    try:
        stt = SpeechToText(use_cloud=False, model_name="base")
        languages = stt.get_supported_languages()
        stt.cleanup()
        
        return {"languages": languages, "total": len(languages)}
    except Exception as e:
        logger.error(f"List languages error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


class SynthesizeRequest(BaseModel):
    text: str
    voice: Optional[str] = None
    rate: Optional[int] = None
    pitch: Optional[float] = None
    use_cache: bool = True


@router.post("/synthesize")
async def synthesize_speech(request: SynthesizeRequest):
    """Synthesize text to speech"""
    try:
        if not request.text or not request.text.strip():
            raise HTTPException(status_code=400, detail="Text cannot be empty")
        
        tts = get_tts()
        
        if request.voice or request.rate or request.pitch:
            update_params = {}
            if request.voice:
                update_params['voice'] = request.voice
            if request.rate:
                update_params['rate'] = request.rate
            if request.pitch:
                update_params['pitch'] = request.pitch
            tts.update_config(**update_params)
        
        audio_data = tts.synthesize(request.text, use_cache=request.use_cache)
        
        return StreamingResponse(
            io.BytesIO(audio_data),
            media_type="audio/wav",
            headers={
                "Content-Disposition": "attachment; filename=speech.wav"
            }
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"TTS synthesis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/speak")
async def speak_text(request: SynthesizeRequest, background_tasks: BackgroundTasks):
    """Synthesize and play text to speech"""
    try:
        if not request.text or not request.text.strip():
            raise HTTPException(status_code=400, detail="Text cannot be empty")
        
        tts = get_tts()
        
        if request.voice or request.rate or request.pitch:
            update_params = {}
            if request.voice:
                update_params['voice'] = request.voice
            if request.rate:
                update_params['rate'] = request.rate
            if request.pitch:
                update_params['pitch'] = request.pitch
            tts.update_config(**update_params)
        
        audio_data = tts.speak(request.text, blocking=False)
        
        return {
            "status": "speaking",
            "text": request.text,
            "audio_size_bytes": len(audio_data) if audio_data else 0
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"TTS speak error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tts/cache/stats")
async def get_tts_cache_stats():
    """Get TTS cache statistics"""
    try:
        tts = get_tts()
        stats = tts.get_cache_stats()
        return stats
    except Exception as e:
        logger.error(f"Get cache stats error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tts/cache/clear")
async def clear_tts_cache():
    """Clear TTS cache"""
    try:
        tts = get_tts()
        tts.clear_cache()
        return {"status": "success", "message": "TTS cache cleared"}
    except Exception as e:
        logger.error(f"Clear cache error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tts/voices")
async def list_tts_voices():
    """List available TTS voices"""
    try:
        tts = get_tts()
        
        if isinstance(tts.engine, type(tts.engine)) and hasattr(tts.engine, 'get_available_voices'):
            voices = tts.engine.get_available_voices()
            return {"voices": voices, "total": len(voices)}
        
        return {
            "voices": [
                {"id": "female", "name": "Female Voice"},
                {"id": "male", "name": "Male Voice"},
                {"id": "neutral", "name": "Neutral Voice"}
            ],
            "total": 3
        }
    except Exception as e:
        logger.error(f"List voices error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.on_event("shutdown")
async def shutdown_voice_services():
    global stt_instance, wake_word_detector, audio_handler, tts_instance
    
    if stt_instance:
        stt_instance.cleanup()
        stt_instance = None
    
    if wake_word_detector:
        wake_word_detector.cleanup()
        wake_word_detector = None
    
    if audio_handler:
        audio_handler.cleanup()
        audio_handler = None
    
    if tts_instance:
        tts_instance.cleanup()
        tts_instance = None
    
    logger.info("Voice services shut down")


@router.post("/pipeline/start")
async def start_pipeline(
    wake_word: Optional[str] = None,
    session_timeout_minutes: int = 5,
    continuous_mode: bool = True
):
    """Start the end-to-end voice pipeline"""
    try:
        config = PipelineConfig(
            wake_word=wake_word or settings.wake_word,
            wake_word_sensitivity=0.5,
            porcupine_access_key=settings.porcupine_api_key,
            use_porcupine=bool(settings.porcupine_api_key),
            stt_model="base",
            stt_use_cloud=settings.voice_provider == "openai",
            stt_api_key=settings.openai_api_key,
            tts_provider=settings.voice_provider or "pyttsx3",
            tts_voice="female",
            tts_api_key=settings.openai_api_key,
            session_timeout_minutes=session_timeout_minutes,
            enable_continuous_mode=continuous_mode
        )
        
        pipeline = get_pipeline(config)
        
        if pipeline.is_running:
            return {
                "status": "already_running",
                "message": "Pipeline is already running"
            }
        
        pipeline.start()
        
        return {
            "status": "success",
            "message": "Voice pipeline started successfully",
            "config": {
                "wake_word": config.wake_word,
                "session_timeout_minutes": config.session_timeout_minutes,
                "continuous_mode": config.enable_continuous_mode
            }
        }
    
    except Exception as e:
        logger.error(f"Failed to start pipeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pipeline/stop")
async def stop_pipeline():
    """Stop the voice pipeline"""
    try:
        pipeline = get_pipeline()
        
        if not pipeline.is_running:
            return {
                "status": "not_running",
                "message": "Pipeline is not running"
            }
        
        pipeline.stop()
        
        return {
            "status": "success",
            "message": "Voice pipeline stopped successfully"
        }
    
    except Exception as e:
        logger.error(f"Failed to stop pipeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pipeline/status")
async def get_pipeline_status():
    """Get voice pipeline status and statistics"""
    try:
        pipeline = get_pipeline()
        stats = pipeline.get_stats()
        
        return {
            "status": "running" if stats["is_running"] else "stopped",
            "stats": stats
        }
    
    except Exception as e:
        logger.error(f"Failed to get pipeline status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/pipeline/process-audio")
async def process_audio_through_pipeline(
    file: UploadFile = File(...),
    session_id: Optional[str] = None
):
    """Process audio file through the complete pipeline (STT → LLM → TTS)"""
    try:
        audio_bytes = await file.read()
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
        temp_file.write(audio_bytes)
        temp_file.close()
        
        try:
            import wave
            with wave.open(temp_file.name, 'rb') as wf:
                frames = wf.readframes(wf.getnframes())
                audio_array = np.frombuffer(frames, dtype=np.int16)
            
            pipeline = get_pipeline()
            
            if not pipeline.is_running:
                pipeline.initialize()
            
            response_text = await pipeline.process_voice_request(
                audio_array,
                session_id=session_id
            )
            
            return {
                "status": "success",
                "response": response_text,
                "session_id": session_id or "default"
            }
        
        finally:
            os.unlink(temp_file.name)
    
    except Exception as e:
        logger.error(f"Pipeline processing error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
