from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def setup_logger(
    name: str = "phantomrecon",
    level: int = logging.INFO,
    log_file: str = "",
) -> logging.Logger:
    """Configure and return a rich-formatted logger."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    rich_handler = RichHandler(
        console=console,
        show_path=False,
        show_time=True,
        markup=True,
        rich_tracebacks=True,
    )
    rich_handler.setLevel(level)
    fmt = "%(message)s"
    rich_handler.setFormatter(logging.Formatter(fmt))
    logger.addHandler(rich_handler)

    if log_file:
        fh = logging.FileHandler(log_file, mode="a")
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s"))
        logger.addHandler(fh)

    return logger


log = setup_logger()
