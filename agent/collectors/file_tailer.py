"""Watchdog-based log file tailer with inode-aware rotation handling.

Tails one or more log files in real time, feeding new lines through
the appropriate parser and publishing NormalizedEvents to the event bus.
Survives log rotation by detecting inode changes and reopening files.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from pathlib import Path

from watchdog.events import DirModifiedEvent, FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from agent.event_bus import EventBus
from agent.parsers.base import LogParser

__all__ = ["FileTailer"]

logger = logging.getLogger(__name__)


class _TailState:
    """Tracks file position and inode for a single tailed file."""

    __slots__ = ("path", "offset", "inode")

    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset: int = 0
        self.inode: int = 0

    def detect_rotation(self) -> bool:
        """Return True if the file's inode changed (log rotation)."""
        try:
            current_inode = os.stat(self.path).st_ino
        except FileNotFoundError:
            return False
        if self.inode != 0 and current_inode != self.inode:
            logger.info("Log rotation detected for %s", self.path)
            self.offset = 0
            self.inode = current_inode
            return True
        self.inode = current_inode
        return False


class _FileEventHandler(FileSystemEventHandler):
    """Watchdog handler that signals an asyncio event on file modification."""

    def __init__(self, notify: asyncio.Event, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._notify = notify
        self._loop = loop

    def on_modified(self, event: DirModifiedEvent | FileModifiedEvent) -> None:
        self._loop.call_soon_threadsafe(self._notify.set)


class FileTailer:
    """Tails log files and publishes parsed events to the event bus.

    Usage::

        tailer = FileTailer(event_bus)
        tailer.add_source(Path("/var/log/auth.log"), auth_parser)
        tailer.add_source(Path("/var/log/syslog"), syslog_parser)
        await tailer.start()  # runs until cancelled
    """

    def __init__(self, event_bus: EventBus, poll_interval: float = 0.5) -> None:
        self._event_bus = event_bus
        self._sources: list[tuple[_TailState, LogParser]] = []
        self._poll_interval = poll_interval
        self._running = False

    def add_source(self, path: Path, parser: LogParser) -> None:
        """Register a log file to tail with its corresponding parser."""
        if not path.exists():
            logger.warning("Log source %s does not exist, skipping", path)
            return
        state = _TailState(path)
        # Start at end of file to avoid replaying historical logs on startup
        try:
            state.offset = path.stat().st_size
            state.inode = os.stat(path).st_ino
        except OSError:
            state.offset = 0
        self._sources.append((state, parser))
        logger.info("Registered log source: %s", path)

    async def start(self) -> None:
        """Begin tailing all registered sources. Blocks until cancelled."""
        if not self._sources:
            logger.warning("No log sources registered")
            return

        loop = asyncio.get_running_loop()
        notify = asyncio.Event()
        handler = _FileEventHandler(notify, loop)
        observer = Observer()

        watched_dirs: set[str] = set()
        for state, _ in self._sources:
            parent = str(state.path.parent)
            if parent not in watched_dirs:
                observer.schedule(handler, parent, recursive=False)
                watched_dirs.add(parent)

        observer.start()
        self._running = True
        logger.info("File tailer started, watching %d sources", len(self._sources))

        try:
            while self._running:
                await self._read_all_sources()
                notify.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(notify.wait(), timeout=self._poll_interval)
        finally:
            observer.stop()
            observer.join()
            logger.info("File tailer stopped")

    async def stop(self) -> None:
        """Signal the tailer to stop."""
        self._running = False

    async def _read_all_sources(self) -> None:
        """Read new lines from all registered log sources."""
        for state, parser in self._sources:
            state.detect_rotation()
            await self._read_source(state, parser)

    async def _read_source(self, state: _TailState, parser: LogParser) -> None:
        """Read new lines from a single log file and publish parsed events."""
        try:
            with open(state.path, encoding="utf-8", errors="replace") as f:
                f.seek(state.offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    event = parser.parse_line(line)
                    if event is not None:
                        await self._event_bus.publish(event)
                state.offset = f.tell()
        except FileNotFoundError:
            logger.debug("File %s not found, will retry", state.path)
        except PermissionError:
            logger.warning("Permission denied reading %s", state.path)
