import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import Config
from ui.display import get_midnight_gradient_text


def setup_logger(name: str = "EVIL_LOCK", log_file: str = None, log_level: str = None) -> logging.Logger:
    logger = logging.getLogger(name)
    
    if logger.handlers:
        return logger
    
    level = getattr(logging, (log_level or Config.LOG_LEVEL).upper(), logging.INFO)
    logger.setLevel(level)
    
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    class GradientFormatter(logging.Formatter):
        def format(self, record):
            message = super().format(record)
            return get_midnight_gradient_text(message)
    
    simple_formatter = GradientFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    if log_file is None:
        log_file = Config.LOG_FILE
    
    try:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=Config.LOG_MAX_SIZE_MB * 1024 * 1024,
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    except (PermissionError, OSError) as e:
        logger.warning(f"Could not create log file '{log_file}': {e}. Logging to console only.")
    
    return logger


default_logger = setup_logger()
