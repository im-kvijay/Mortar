"""correlation id management for audit traceability this module provides correlation id (audit_id) m..."""
import uuid
import threading
from contextvars import ContextVar
from typing import Optional


# context variable for async-safe correlation id
_audit_id: ContextVar[Optional[str]] = ContextVar('audit_id', default=None)

# thread-local storage as fallback for sync contexts
_thread_local = threading.local()


def generate_audit_id() -> str:
    """generate a new audit id. returns: 8-character hex string (e.g., "a3f9b2c4")"""
    return str(uuid.uuid4())[:8]


def set_audit_id(audit_id: str) -> None:
    """set the current audit id for this context. args: audit_id: audit id to set"""
    _audit_id.set(audit_id)
    _thread_local.audit_id = audit_id


def get_audit_id() -> Optional[str]:
    """get the current audit id. returns: current audit id or none if not in audit context"""
#    # try context var first (async-safe), then thread local
    ctx_id = _audit_id.get()
    if ctx_id is not None:
        return ctx_id

    return getattr(_thread_local, 'audit_id', None)


def clear_audit_id() -> None:
    """clear the current audit id. should only be called by auditcontext.__exit__ to restore previous st..."""
    _audit_id.set(None)
    if hasattr(_thread_local, 'audit_id'):
        delattr(_thread_local, 'audit_id')


class auditcontext:
    """context manager for audit correlation. usage: # # generate new audit id with auditcontext() as au..."""

    def __init__(self, audit_id: Optional[str] = None):
        """initialize audit context. args: audit_id: existing audit id to use (generates new if none)"""
        self.audit_id = audit_id or generate_audit_id()
        self.previous_id: Optional[str] = None

    def __enter__(self) -> str:
        """enter audit context - sets audit_id. returns: current audit id"""
        self.previous_id = get_audit_id()
        set_audit_id(self.audit_id)
        return self.audit_id

    def __exit__(self, *args):
        """exit audit context - restores previous audit_id."""
        if self.previous_id is not None:
            set_audit_id(self.previous_id)
        else:
            clear_audit_id()
