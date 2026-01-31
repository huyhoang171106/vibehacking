"""
Unified Error Handler for HexStrike AI

Consolidates error handling with:
- Intelligent error classification
- Recovery strategies
- Retry mechanisms with exponential backoff
- Error logging and metrics
"""

import time
import traceback
import logging
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, TypeVar, Union
from enum import Enum, auto
from functools import wraps

logger = logging.getLogger(__name__)

T = TypeVar('T')


class ErrorType(Enum):
    """Classification of error types."""
    # Network errors
    NETWORK_TIMEOUT = auto()
    NETWORK_CONNECTION = auto()
    NETWORK_DNS = auto()
    NETWORK_SSL = auto()

    # Tool execution errors
    TOOL_NOT_FOUND = auto()
    TOOL_TIMEOUT = auto()
    TOOL_PERMISSION = auto()
    TOOL_CRASH = auto()
    TOOL_OUTPUT_PARSE = auto()

    # Resource errors
    RESOURCE_NOT_FOUND = auto()
    RESOURCE_PERMISSION = auto()
    RESOURCE_EXHAUSTED = auto()

    # Input/validation errors
    INVALID_INPUT = auto()
    INVALID_TARGET = auto()
    INVALID_PARAMETER = auto()

    # Authentication errors
    AUTH_FAILED = auto()
    AUTH_EXPIRED = auto()
    AUTH_INSUFFICIENT = auto()

    # Rate limiting
    RATE_LIMITED = auto()

    # System errors
    SYSTEM_MEMORY = auto()
    SYSTEM_DISK = auto()
    SYSTEM_PROCESS = auto()

    # Unknown/generic
    UNKNOWN = auto()


class RecoveryStrategy(Enum):
    """Available recovery strategies."""
    RETRY = auto()
    RETRY_WITH_BACKOFF = auto()
    RETRY_WITH_FALLBACK = auto()
    SKIP = auto()
    ABORT = auto()
    WAIT_AND_RETRY = auto()
    USE_ALTERNATIVE = auto()
    REDUCE_SCOPE = auto()
    MANUAL_INTERVENTION = auto()


@dataclass
class ErrorContext:
    """Context information for an error."""
    error_type: ErrorType
    message: str
    original_exception: Optional[Exception] = None
    stack_trace: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    operation: Optional[str] = None
    target: Optional[str] = None
    tool: Optional[str] = None
    attempt_number: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/serialization."""
        return {
            "error_type": self.error_type.name,
            "message": self.message,
            "original_exception": str(self.original_exception) if self.original_exception else None,
            "timestamp": self.timestamp,
            "operation": self.operation,
            "target": self.target,
            "tool": self.tool,
            "attempt_number": self.attempt_number,
            "metadata": self.metadata,
        }


@dataclass
class RecoveryResult:
    """Result of a recovery attempt."""
    success: bool
    strategy_used: RecoveryStrategy
    attempts: int
    final_error: Optional[ErrorContext] = None
    result: Any = None
    recovery_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "strategy": self.strategy_used.name,
            "attempts": self.attempts,
            "recovery_time": round(self.recovery_time, 3),
            "final_error": self.final_error.to_dict() if self.final_error else None,
        }


class UnifiedErrorHandler:
    """
    Unified error handling system for HexStrike AI.

    Provides:
    - Error classification from messages and exceptions
    - Appropriate recovery strategy selection
    - Retry mechanisms with configurable policies
    - Error logging and metrics
    """

    # Error message patterns for classification
    ERROR_PATTERNS: Dict[ErrorType, List[str]] = {
        ErrorType.NETWORK_TIMEOUT: [
            r"timeout", r"timed out", r"connection timed out",
            r"read timeout", r"connect timeout"
        ],
        ErrorType.NETWORK_CONNECTION: [
            r"connection refused", r"connection reset", r"connection error",
            r"failed to connect", r"no route to host", r"network unreachable"
        ],
        ErrorType.NETWORK_DNS: [
            r"name resolution", r"dns", r"could not resolve",
            r"getaddrinfo failed", r"nodename nor servname"
        ],
        ErrorType.NETWORK_SSL: [
            r"ssl", r"certificate", r"handshake", r"tls"
        ],
        ErrorType.TOOL_NOT_FOUND: [
            r"command not found", r"not found", r"no such file",
            r"executable not found", r"tool not available"
        ],
        ErrorType.TOOL_TIMEOUT: [
            r"process timeout", r"execution timeout", r"killed",
            r"exceeded time limit"
        ],
        ErrorType.TOOL_PERMISSION: [
            r"permission denied", r"access denied", r"operation not permitted",
            r"insufficient privileges", r"root required", r"sudo"
        ],
        ErrorType.RESOURCE_NOT_FOUND: [
            r"file not found", r"no such file", r"does not exist",
            r"404", r"not found"
        ],
        ErrorType.RESOURCE_PERMISSION: [
            r"permission denied", r"access denied", r"forbidden", r"403"
        ],
        ErrorType.RESOURCE_EXHAUSTED: [
            r"disk full", r"no space left", r"quota exceeded",
            r"too many open files", r"memory exhausted"
        ],
        ErrorType.INVALID_INPUT: [
            r"invalid input", r"malformed", r"parse error",
            r"syntax error", r"validation failed"
        ],
        ErrorType.INVALID_TARGET: [
            r"invalid target", r"invalid host", r"invalid url",
            r"invalid address", r"unreachable"
        ],
        ErrorType.AUTH_FAILED: [
            r"authentication failed", r"login failed", r"invalid credentials",
            r"unauthorized", r"401"
        ],
        ErrorType.AUTH_EXPIRED: [
            r"token expired", r"session expired", r"expired"
        ],
        ErrorType.RATE_LIMITED: [
            r"rate limit", r"too many requests", r"429",
            r"slow down", r"throttl"
        ],
        ErrorType.SYSTEM_MEMORY: [
            r"out of memory", r"memory error", r"cannot allocate",
            r"killed.*oom"
        ],
    }

    # Default recovery strategies by error type
    DEFAULT_STRATEGIES: Dict[ErrorType, RecoveryStrategy] = {
        ErrorType.NETWORK_TIMEOUT: RecoveryStrategy.RETRY_WITH_BACKOFF,
        ErrorType.NETWORK_CONNECTION: RecoveryStrategy.RETRY_WITH_BACKOFF,
        ErrorType.NETWORK_DNS: RecoveryStrategy.RETRY,
        ErrorType.NETWORK_SSL: RecoveryStrategy.ABORT,
        ErrorType.TOOL_NOT_FOUND: RecoveryStrategy.ABORT,
        ErrorType.TOOL_TIMEOUT: RecoveryStrategy.RETRY_WITH_BACKOFF,
        ErrorType.TOOL_PERMISSION: RecoveryStrategy.ABORT,
        ErrorType.TOOL_CRASH: RecoveryStrategy.RETRY,
        ErrorType.RESOURCE_NOT_FOUND: RecoveryStrategy.ABORT,
        ErrorType.RESOURCE_PERMISSION: RecoveryStrategy.ABORT,
        ErrorType.RESOURCE_EXHAUSTED: RecoveryStrategy.WAIT_AND_RETRY,
        ErrorType.INVALID_INPUT: RecoveryStrategy.ABORT,
        ErrorType.INVALID_TARGET: RecoveryStrategy.ABORT,
        ErrorType.AUTH_FAILED: RecoveryStrategy.ABORT,
        ErrorType.AUTH_EXPIRED: RecoveryStrategy.ABORT,
        ErrorType.RATE_LIMITED: RecoveryStrategy.WAIT_AND_RETRY,
        ErrorType.SYSTEM_MEMORY: RecoveryStrategy.ABORT,
        ErrorType.UNKNOWN: RecoveryStrategy.RETRY,
    }

    def __init__(self,
                 max_retries: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_base: float = 2.0):
        """
        Initialize error handler.

        Args:
            max_retries: Maximum retry attempts
            base_delay: Base delay for backoff (seconds)
            max_delay: Maximum delay between retries
            exponential_base: Base for exponential backoff
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base

        # Compile patterns for efficiency
        self._compiled_patterns: Dict[ErrorType, List[re.Pattern]] = {}
        for error_type, patterns in self.ERROR_PATTERNS.items():
            self._compiled_patterns[error_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        # Error statistics
        self._error_counts: Dict[ErrorType, int] = {t: 0 for t in ErrorType}
        self._recovery_success: Dict[RecoveryStrategy, int] = {s: 0 for s in RecoveryStrategy}
        self._recovery_failure: Dict[RecoveryStrategy, int] = {s: 0 for s in RecoveryStrategy}

    def classify_error(self,
                      message: str,
                      exception: Optional[Exception] = None) -> ErrorType:
        """
        Classify an error based on message and/or exception.

        Args:
            message: Error message
            exception: Original exception (optional)

        Returns:
            Classified ErrorType
        """
        # Combine message with exception info
        full_message = message.lower()
        if exception:
            full_message += " " + str(exception).lower()
            full_message += " " + type(exception).__name__.lower()

        # Check patterns
        for error_type, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(full_message):
                    self._error_counts[error_type] += 1
                    return error_type

        # Check exception type directly
        if exception:
            exception_mappings = {
                "timeout": ErrorType.NETWORK_TIMEOUT,
                "connectionerror": ErrorType.NETWORK_CONNECTION,
                "connectionrefused": ErrorType.NETWORK_CONNECTION,
                "filenotfounderror": ErrorType.RESOURCE_NOT_FOUND,
                "permissionerror": ErrorType.RESOURCE_PERMISSION,
                "memoryerror": ErrorType.SYSTEM_MEMORY,
                "valueerror": ErrorType.INVALID_INPUT,
            }

            exc_name = type(exception).__name__.lower()
            for key, error_type in exception_mappings.items():
                if key in exc_name:
                    self._error_counts[error_type] += 1
                    return error_type

        self._error_counts[ErrorType.UNKNOWN] += 1
        return ErrorType.UNKNOWN

    def get_recovery_strategy(self,
                             error_type: ErrorType,
                             context: Optional[ErrorContext] = None) -> RecoveryStrategy:
        """
        Get recommended recovery strategy for an error.

        Args:
            error_type: Type of error
            context: Additional error context

        Returns:
            Recommended RecoveryStrategy
        """
        # Check for repeated failures
        if context and context.attempt_number >= self.max_retries:
            return RecoveryStrategy.ABORT

        return self.DEFAULT_STRATEGIES.get(error_type, RecoveryStrategy.RETRY)

    def create_context(self,
                      message: str,
                      exception: Optional[Exception] = None,
                      operation: Optional[str] = None,
                      target: Optional[str] = None,
                      tool: Optional[str] = None,
                      **metadata) -> ErrorContext:
        """
        Create an error context with classification.

        Args:
            message: Error message
            exception: Original exception
            operation: What operation was being performed
            target: Target of the operation
            tool: Tool being used
            **metadata: Additional metadata

        Returns:
            ErrorContext with classified error type
        """
        error_type = self.classify_error(message, exception)
        stack_trace = None

        if exception:
            stack_trace = "".join(traceback.format_exception(
                type(exception), exception, exception.__traceback__
            ))

        return ErrorContext(
            error_type=error_type,
            message=message,
            original_exception=exception,
            stack_trace=stack_trace,
            operation=operation,
            target=target,
            tool=tool,
            metadata=metadata
        )

    def handle_with_retry(self,
                         func: Callable[..., T],
                         *args,
                         max_retries: Optional[int] = None,
                         on_retry: Optional[Callable[[int, Exception], None]] = None,
                         **kwargs) -> RecoveryResult:
        """
        Execute function with automatic retry on failure.

        Args:
            func: Function to execute
            *args: Function arguments
            max_retries: Override default max retries
            on_retry: Callback on each retry (attempt_num, exception)
            **kwargs: Function keyword arguments

        Returns:
            RecoveryResult with success status and result
        """
        retries = max_retries if max_retries is not None else self.max_retries
        start_time = time.time()
        last_error: Optional[ErrorContext] = None
        strategy_used = RecoveryStrategy.RETRY

        for attempt in range(1, retries + 1):
            try:
                result = func(*args, **kwargs)
                self._recovery_success[strategy_used] += 1

                return RecoveryResult(
                    success=True,
                    strategy_used=strategy_used,
                    attempts=attempt,
                    result=result,
                    recovery_time=time.time() - start_time
                )

            except Exception as e:
                last_error = self.create_context(
                    message=str(e),
                    exception=e,
                    operation=func.__name__ if hasattr(func, '__name__') else str(func)
                )
                last_error.attempt_number = attempt

                logger.warning(
                    f"Attempt {attempt}/{retries} failed: {last_error.error_type.name} - {e}"
                )

                # Get recovery strategy
                strategy = self.get_recovery_strategy(last_error.error_type, last_error)
                strategy_used = strategy

                if strategy == RecoveryStrategy.ABORT:
                    break

                if attempt < retries:
                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(attempt, e)
                        except Exception:
                            pass

                    # Calculate delay
                    if strategy == RecoveryStrategy.RETRY_WITH_BACKOFF:
                        delay = self._calculate_backoff_delay(attempt)
                    elif strategy == RecoveryStrategy.WAIT_AND_RETRY:
                        delay = self._get_wait_time(last_error)
                    else:
                        delay = self.base_delay

                    logger.info(f"Waiting {delay:.1f}s before retry...")
                    time.sleep(delay)

        self._recovery_failure[strategy_used] += 1

        return RecoveryResult(
            success=False,
            strategy_used=strategy_used,
            attempts=retries,
            final_error=last_error,
            recovery_time=time.time() - start_time
        )

    def _calculate_backoff_delay(self, attempt: int) -> float:
        """Calculate exponential backoff delay."""
        delay = self.base_delay * (self.exponential_base ** (attempt - 1))
        # Add jitter (±10%)
        import random
        jitter = delay * 0.1 * (random.random() * 2 - 1)
        delay = min(delay + jitter, self.max_delay)
        return max(0, delay)

    def _get_wait_time(self, context: ErrorContext) -> float:
        """Get wait time for rate limiting or resource exhaustion."""
        # Check for Retry-After header in metadata
        retry_after = context.metadata.get("retry_after")
        if retry_after:
            try:
                return float(retry_after)
            except (TypeError, ValueError):
                pass

        # Default wait times by error type
        wait_times = {
            ErrorType.RATE_LIMITED: 30.0,
            ErrorType.RESOURCE_EXHAUSTED: 60.0,
        }

        return wait_times.get(context.error_type, self.base_delay)

    def get_stats(self) -> Dict[str, Any]:
        """Get error handling statistics."""
        return {
            "error_counts": {t.name: c for t, c in self._error_counts.items() if c > 0},
            "recovery_success": {s.name: c for s, c in self._recovery_success.items() if c > 0},
            "recovery_failure": {s.name: c for s, c in self._recovery_failure.items() if c > 0},
        }


def with_error_handling(handler: Optional[UnifiedErrorHandler] = None,
                       max_retries: int = 3,
                       on_error: Optional[Callable[[ErrorContext], None]] = None):
    """
    Decorator for automatic error handling.

    Args:
        handler: Error handler instance (creates default if None)
        max_retries: Maximum retry attempts
        on_error: Callback on final error

    Returns:
        Decorated function
    """
    error_handler = handler or UnifiedErrorHandler(max_retries=max_retries)

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            result = error_handler.handle_with_retry(func, *args, **kwargs)

            if result.success:
                return result.result
            else:
                if on_error and result.final_error:
                    on_error(result.final_error)
                raise RuntimeError(
                    f"Operation failed after {result.attempts} attempts: "
                    f"{result.final_error.message if result.final_error else 'Unknown error'}"
                )

        return wrapper
    return decorator


# Singleton instance for convenience
_default_handler: Optional[UnifiedErrorHandler] = None


def get_default_handler() -> UnifiedErrorHandler:
    """Get or create the default error handler."""
    global _default_handler
    if _default_handler is None:
        _default_handler = UnifiedErrorHandler()
    return _default_handler


def classify_error(message: str, exception: Optional[Exception] = None) -> ErrorType:
    """Quick function to classify an error."""
    return get_default_handler().classify_error(message, exception)


def get_recovery_strategy(error_type: ErrorType) -> RecoveryStrategy:
    """Quick function to get recovery strategy."""
    return get_default_handler().get_recovery_strategy(error_type)
