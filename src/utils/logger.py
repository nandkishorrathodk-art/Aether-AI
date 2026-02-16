import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional

from src.config import settings


class AetherLogger:
    _instance: Optional[logging.Logger] = None

    @classmethod
    def get_logger(cls, name: str = "aether") -> logging.Logger:
        if cls._instance is not None:
            return cls._instance

        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, settings.log_level.upper()))

        if logger.handlers:
            return logger

        log_format = logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(log_format)
        logger.addHandler(console_handler)

        settings.log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            filename=settings.log_file,
            maxBytes=settings.log_max_size_mb * 1024 * 1024,
            backupCount=settings.log_backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(log_format)
        logger.addHandler(file_handler)

        logger.propagate = False

        cls._instance = logger
        logger.info(f"Logger initialized: {name}")

        return logger


def get_logger(name: str = "aether") -> logging.Logger:
    return AetherLogger.get_logger(name)
