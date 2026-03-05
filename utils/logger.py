import sys
import logging
import os

LOG_DIR  = "logs"
LOG_FILE = os.path.join(LOG_DIR, "analyzer.log")

os.makedirs(LOG_DIR, exist_ok=True)

# File handler — full detailed logs saved to file
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
))

# Terminal handler — clean, no timestamps
terminal_handler = logging.StreamHandler(sys.stdout)
terminal_handler.setLevel(logging.INFO)
terminal_handler.setFormatter(logging.Formatter("%(message)s"))

logging.basicConfig(level=logging.INFO, handlers=[file_handler, terminal_handler])

def get_logger(name: str) -> logging.Logger:
    """Returns a named logger for any module."""
    return logging.getLogger(name)