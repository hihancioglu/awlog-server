import os
import logging

DEBUG_MODE = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")

def DEBUG(message: str) -> None:
    """Log debug message when DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        logging.info(f"[DEBUG] {message}")
