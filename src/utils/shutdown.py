"""graceful shutdown handling for production deployments. purpose: ensures clean termination of mort..."""

import signal
import sys
import threading
import atexit
import logging
import json
from pathlib import Path
from typing import Callable, List, Optional, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ShutdownManager:
    """manages graceful shutdown of the application. singleton pattern ensures coordinated shutdown acro..."""

    _instance: Optional["ShutdownManager"] = None
    _lock = threading.Lock()

    def __init__(self):
        """initialize shutdown manager (private - use get_instance())"""
        self._shutdown_requested = threading.Event()
        self._cleanup_handlers: List[Tuple[Callable[[], None], str]] = []
        self._executors: List[ThreadPoolExecutor] = []
        self._handlers_lock = threading.Lock()
        self._cleanup_done = threading.Event()  # prevent double-cleanup
        self._cleanup_lock = threading.Lock()   # non-blocking lock for cleanup
        self._shutdown_reason: Optional[str] = None
        self._partial_results: Dict[str, Any] = {}
        self._partial_results_file: Optional[Path] = None
        self._setup_signal_handlers()

    @classmethod
    def get_instance(cls) -> "ShutdownManager":
        """get singleton instance. thread-safe lazy initialization."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _setup_signal_handlers(self):
        """set up signal handlers for graceful shutdown. handles: - sigterm (kill) - sigint (ctrl+c) - norma..."""
        try:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            atexit.register(self._atexit_handler)
            logger.debug("Shutdown handlers registered successfully")
        except Exception as e:
            logger.warning(f"Failed to register shutdown handlers: {e}")

    def _signal_handler(self, signum, frame):
        """handle shutdown signals (sigterm, sigint). critical: signal handlers must not call blocking i/o f..."""
        try:
            signal_name = signal.Signals(signum).name
            self._shutdown_reason = signal_name
        except (ValueError, AttributeError):
            self._shutdown_reason = f"signal_{signum}"

        self._shutdown_requested.set()

        exit_code = 128 + signum  # standard unix convention
        sys.exit(exit_code)

    def _atexit_handler(self):
        """handle normal exit cleanup. called automatically by atexit on normal program termination. safe to..."""
#        # run cleanup regardless of shutdown flag
#        # _run_cleanup() is idempotent and thread-safe
        self._run_cleanup()

    def register_cleanup(self, handler: Callable[[], None], name: str = None):
        """register a cleanup handler to run on shutdown. handlers are executed in reverse order of registra..."""
        handler_name = name or getattr(handler, '__name__', 'unknown')
        with self._handlers_lock:
            self._cleanup_handlers.append((handler, handler_name))
        logger.debug(f"Registered cleanup handler: {handler_name}")

    def register_executor(self, executor: ThreadPoolExecutor):
        """register a threadpoolexecutor to be shut down gracefully. executors are shut down before cleanup ..."""
        with self._handlers_lock:
            self._executors.append(executor)
        logger.debug(f"Registered executor for shutdown: {id(executor)}")

    def is_shutdown_requested(self) -> bool:
        """check if shutdown has been requested. returns: true if shutdown signal received, false otherwise ..."""
        return self._shutdown_requested.is_set()

    def request_shutdown(self, reason: str = "programmatic"):
        """manually request shutdown (for programmatic use). equivalent to sending sigterm, but without the ..."""
        logger.info(f"Programmatic shutdown requested: {reason}")
        self._shutdown_reason = reason
        self._shutdown_requested.set()

    def set_partial_results_file(self, file_path: Path):
        """set the file path for saving partial results on shutdown. args: file_path: path to save partial r..."""
        self._partial_results_file = file_path
        logger.debug(f"Partial results will be saved to: {file_path}")

    def update_partial_results(self, key: str, value: Any):
        """update partial results that will be saved on shutdown. args: key: result key (e.g., "contract_nam..."""
        with self._handlers_lock:
            self._partial_results[key] = value

    def save_partial_results(self):
        """save partial results to disk with atomic write. called automatically during shutdown if partial_r..."""
        if not self._partial_results_file or not self._partial_results:
            return

        try:
#            # ensure parent directory exists
            self._partial_results_file.parent.mkdir(parents=True, exist_ok=True)

#            # add metadata
            results = {
                "shutdown_reason": self._shutdown_reason or "unknown",
                "shutdown_time": datetime.now(timezone.utc).isoformat(),
                "partial": True,
                "results": self._partial_results
            }

#            # atomic write: write to temp file, then rename
#            # this prevents partial/corrupted writes if interrupted
            temp_file = self._partial_results_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)

#            # atomic rename (posix guarantees atomicity)
            temp_file.rename(self._partial_results_file)

            logger.info(f"Partial results saved to: {self._partial_results_file}")

        except BaseException as e:
            logger.error(f"Failed to save partial results: {e}", exc_info=True)

    def _run_cleanup(self):
        """run all registered cleanup handlers. execution order: 1. save partial results (if any) 2. shutdow..."""
#        # non-blocking lock: if another thread is cleaning up, skip
        if not self._cleanup_lock.acquire(blocking=False):
            logger.debug("Cleanup already in progress (another thread), skipping")
            return

        try:
#            # check if cleanup already completed
            if self._cleanup_done.is_set():
                logger.debug("Cleanup already completed, skipping")
                return

            logger.info(f"Running shutdown cleanup (reason: {self._shutdown_reason or 'unknown'})...")

#            # phase 0: save partial results
            try:
                self.save_partial_results()
            except BaseException as e:
                logger.warning(f"Error saving partial results: {e}", exc_info=True)

#            # phase 1: shutdown executors (wait for completion to avoid resource leaks)
            if self._executors:
                logger.debug(f"Shutting down {len(self._executors)} executors...")
                for i, executor in enumerate(self._executors):
                    try:
                        executor.shutdown(wait=True, cancel_futures=True)
                        logger.debug(f"Executor {i+1}/{len(self._executors)} shut down")
                    except BaseException as e:
                        logger.warning(f"Error shutting down executor {id(executor)}: {e}")

            if self._cleanup_handlers:
                logger.debug(f"Running {len(self._cleanup_handlers)} cleanup handlers...")
                for handler, name in reversed(self._cleanup_handlers):
                    try:
                        logger.debug(f"Running cleanup: {name}")
                        handler()
                        logger.debug(f"Cleanup completed: {name}")
                    except BaseException as e:
                        logger.warning(f"Error in cleanup handler '{name}': {e}", exc_info=True)

#            # mark cleanup as done
            self._cleanup_done.set()
            logger.info("Shutdown cleanup complete")

        finally:
#            # always release lock
            self._cleanup_lock.release()


# convenience functions


def get_shutdown_manager() -> ShutdownManager:
    """get the singleton shutdown manager. returns: shutdownmanager instance"""
    return ShutdownManager.get_instance()


def register_cleanup(handler: Callable[[], None], name: str = None):
    """convenience function to register a cleanup handler. args: handler: cleanup function (must be idem..."""
    get_shutdown_manager().register_cleanup(handler, name)


def register_executor(executor: ThreadPoolExecutor):
    """convenience function to register an executor for shutdown. args: executor: threadpoolexecutor ins..."""
    get_shutdown_manager().register_executor(executor)


def is_shutdown_requested() -> bool:
    """check if shutdown has been requested. returns: true if shutdown in progress, false otherwise exam..."""
    return get_shutdown_manager().is_shutdown_requested()


def request_shutdown(reason: str = "programmatic"):
    """manually request shutdown (for programmatic use). args: reason: human-readable reason for shutdow..."""
    get_shutdown_manager().request_shutdown(reason)


def set_partial_results_file(file_path: Path):
    """set the file path for saving partial results on shutdown. args: file_path: path to save partial r..."""
    get_shutdown_manager().set_partial_results_file(file_path)


def update_partial_results(key: str, value: Any):
    """update partial results that will be saved on shutdown. args: key: result key (e.g., "contract_nam..."""
    get_shutdown_manager().update_partial_results(key, value)
