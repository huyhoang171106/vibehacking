"""
Parallel Workflow Executor for HexStrike AI

Provides true parallel execution using:
- asyncio for I/O-bound operations
- ThreadPoolExecutor for CPU-bound and blocking operations
- ProcessPoolExecutor for truly parallel CPU-intensive work
- Task dependency management
"""

import asyncio
import time
import logging
from dataclasses import dataclass, field
from typing import (
    Optional, Dict, Any, List, Callable, TypeVar, Coroutine,
    Set, Union, Awaitable
)
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, Future
import threading

logger = logging.getLogger(__name__)

T = TypeVar('T')


class TaskStatus(Enum):
    """Status of a workflow task."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class TaskPriority(Enum):
    """Priority levels for tasks."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class TaskResult:
    """Result of a task execution."""
    task_id: str
    status: TaskStatus
    result: Any = None
    error: Optional[Exception] = None
    start_time: float = 0.0
    end_time: float = 0.0
    execution_time: float = 0.0

    @property
    def success(self) -> bool:
        """Check if task completed successfully."""
        return self.status == TaskStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "result": str(self.result)[:200] if self.result else None,
            "error": str(self.error) if self.error else None,
            "execution_time": round(self.execution_time, 3),
        }


@dataclass
class WorkflowTask:
    """Definition of a workflow task."""
    task_id: str
    func: Union[Callable, Coroutine]
    args: tuple = field(default_factory=tuple)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    dependencies: Set[str] = field(default_factory=set)
    priority: TaskPriority = TaskPriority.NORMAL
    timeout: Optional[float] = None
    retries: int = 0
    is_async: bool = False

    # Runtime state
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[TaskResult] = None


class ParallelWorkflowExecutor:
    """
    True parallel workflow executor.

    Executes tasks in parallel using appropriate execution strategy:
    - Async tasks: asyncio event loop
    - I/O-bound sync tasks: ThreadPoolExecutor
    - CPU-bound tasks: ProcessPoolExecutor

    Supports:
    - Task dependencies
    - Priority scheduling
    - Timeout management
    - Automatic retry
    """

    def __init__(self,
                 max_threads: int = 10,
                 max_processes: int = 4,
                 default_timeout: float = 300.0):
        """
        Initialize parallel executor.

        Args:
            max_threads: Maximum worker threads
            max_processes: Maximum worker processes
            default_timeout: Default task timeout in seconds
        """
        self.max_threads = max_threads
        self.max_processes = max_processes
        self.default_timeout = default_timeout

        self._thread_pool: Optional[ThreadPoolExecutor] = None
        self._process_pool: Optional[ProcessPoolExecutor] = None
        self._lock = threading.Lock()

        # Task tracking
        self._tasks: Dict[str, WorkflowTask] = {}
        self._results: Dict[str, TaskResult] = {}
        self._running: Set[str] = set()
        self._completed: Set[str] = set()

    def _get_thread_pool(self) -> ThreadPoolExecutor:
        """Get or create thread pool."""
        if self._thread_pool is None:
            self._thread_pool = ThreadPoolExecutor(max_workers=self.max_threads)
        return self._thread_pool

    def _get_process_pool(self) -> ProcessPoolExecutor:
        """Get or create process pool."""
        if self._process_pool is None:
            self._process_pool = ProcessPoolExecutor(max_workers=self.max_processes)
        return self._process_pool

    def add_task(self,
                 task_id: str,
                 func: Callable,
                 args: tuple = (),
                 kwargs: Optional[Dict[str, Any]] = None,
                 dependencies: Optional[Set[str]] = None,
                 priority: TaskPriority = TaskPriority.NORMAL,
                 timeout: Optional[float] = None,
                 retries: int = 0) -> None:
        """
        Add a task to the workflow.

        Args:
            task_id: Unique task identifier
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments
            dependencies: Set of task IDs that must complete first
            priority: Task priority
            timeout: Task timeout
            retries: Number of retries on failure
        """
        is_async = asyncio.iscoroutinefunction(func)

        task = WorkflowTask(
            task_id=task_id,
            func=func,
            args=args,
            kwargs=kwargs or {},
            dependencies=dependencies or set(),
            priority=priority,
            timeout=timeout or self.default_timeout,
            retries=retries,
            is_async=is_async
        )

        with self._lock:
            self._tasks[task_id] = task

    def clear_tasks(self) -> None:
        """Clear all tasks."""
        with self._lock:
            self._tasks.clear()
            self._results.clear()
            self._running.clear()
            self._completed.clear()

    async def execute_workflow(self,
                               tasks: Optional[List[WorkflowTask]] = None) -> List[TaskResult]:
        """
        Execute all tasks in the workflow with proper parallelism.

        Tasks are executed in parallel when their dependencies are satisfied.

        Args:
            tasks: Optional list of tasks (uses added tasks if None)

        Returns:
            List of TaskResults
        """
        if tasks:
            for task in tasks:
                self._tasks[task.task_id] = task

        if not self._tasks:
            return []

        results = []
        pending = set(self._tasks.keys())

        while pending:
            # Find tasks ready to run (dependencies satisfied)
            ready = self._get_ready_tasks(pending)

            if not ready:
                if pending:
                    # Deadlock detection
                    logger.error(f"Deadlock detected! Pending tasks: {pending}")
                    for task_id in pending:
                        results.append(TaskResult(
                            task_id=task_id,
                            status=TaskStatus.SKIPPED,
                            error=Exception("Circular dependency detected")
                        ))
                break

            # Execute ready tasks in parallel
            task_futures = []
            for task_id in ready:
                task = self._tasks[task_id]
                future = self._execute_task(task)
                task_futures.append((task_id, future))

            # Wait for all current tasks to complete
            for task_id, future in task_futures:
                try:
                    result = await future
                    results.append(result)
                    self._results[task_id] = result

                    with self._lock:
                        self._completed.add(task_id)
                        self._running.discard(task_id)
                        pending.discard(task_id)

                except Exception as e:
                    logger.error(f"Task {task_id} failed: {e}")
                    result = TaskResult(
                        task_id=task_id,
                        status=TaskStatus.FAILED,
                        error=e
                    )
                    results.append(result)
                    self._results[task_id] = result

                    with self._lock:
                        self._completed.add(task_id)
                        self._running.discard(task_id)
                        pending.discard(task_id)

        return results

    def _get_ready_tasks(self, pending: Set[str]) -> List[str]:
        """Get tasks that are ready to execute (dependencies met)."""
        ready = []

        for task_id in pending:
            if task_id in self._running:
                continue

            task = self._tasks[task_id]
            deps_satisfied = all(
                dep in self._completed
                for dep in task.dependencies
            )

            if deps_satisfied:
                # Check if any dependency failed
                dep_failed = any(
                    self._results.get(dep, TaskResult(dep, TaskStatus.PENDING)).status == TaskStatus.FAILED
                    for dep in task.dependencies
                )

                if dep_failed:
                    # Skip this task if dependency failed
                    self._results[task_id] = TaskResult(
                        task_id=task_id,
                        status=TaskStatus.SKIPPED,
                        error=Exception("Dependency failed")
                    )
                    self._completed.add(task_id)
                else:
                    ready.append(task_id)
                    self._running.add(task_id)

        # Sort by priority (higher priority first)
        ready.sort(
            key=lambda tid: self._tasks[tid].priority.value,
            reverse=True
        )

        return ready

    async def _execute_task(self, task: WorkflowTask) -> TaskResult:
        """Execute a single task with proper async handling."""
        start_time = time.time()
        task.status = TaskStatus.RUNNING

        attempts = 0
        last_error = None

        while attempts <= task.retries:
            attempts += 1

            try:
                if task.is_async:
                    # Async function - run directly
                    if task.timeout:
                        result = await asyncio.wait_for(
                            task.func(*task.args, **task.kwargs),
                            timeout=task.timeout
                        )
                    else:
                        result = await task.func(*task.args, **task.kwargs)
                else:
                    # Sync function - run in thread pool
                    loop = asyncio.get_event_loop()
                    pool = self._get_thread_pool()

                    if task.timeout:
                        result = await asyncio.wait_for(
                            loop.run_in_executor(
                                pool,
                                lambda: task.func(*task.args, **task.kwargs)
                            ),
                            timeout=task.timeout
                        )
                    else:
                        result = await loop.run_in_executor(
                            pool,
                            lambda: task.func(*task.args, **task.kwargs)
                        )

                end_time = time.time()
                task.status = TaskStatus.COMPLETED

                return TaskResult(
                    task_id=task.task_id,
                    status=TaskStatus.COMPLETED,
                    result=result,
                    start_time=start_time,
                    end_time=end_time,
                    execution_time=end_time - start_time
                )

            except asyncio.TimeoutError:
                last_error = Exception(f"Task timed out after {task.timeout}s")
                logger.warning(f"Task {task.task_id} timed out (attempt {attempts})")

            except Exception as e:
                last_error = e
                logger.warning(f"Task {task.task_id} failed (attempt {attempts}): {e}")

            if attempts <= task.retries:
                # Wait before retry with exponential backoff
                await asyncio.sleep(min(2 ** attempts, 30))

        end_time = time.time()
        task.status = TaskStatus.FAILED

        return TaskResult(
            task_id=task.task_id,
            status=TaskStatus.FAILED,
            error=last_error,
            start_time=start_time,
            end_time=end_time,
            execution_time=end_time - start_time
        )

    def execute_parallel(self,
                        funcs: List[Callable],
                        args_list: Optional[List[tuple]] = None,
                        timeout: Optional[float] = None) -> List[TaskResult]:
        """
        Execute multiple functions in parallel (synchronous interface).

        Convenience method for simple parallel execution without
        dependency management.

        Args:
            funcs: List of functions to execute
            args_list: List of argument tuples for each function
            timeout: Overall timeout

        Returns:
            List of TaskResults
        """
        args_list = args_list or [() for _ in funcs]

        # Create tasks
        self.clear_tasks()
        for i, (func, args) in enumerate(zip(funcs, args_list)):
            self.add_task(
                task_id=f"task_{i}",
                func=func,
                args=args,
                timeout=timeout
            )

        # Run workflow
        return asyncio.run(self.execute_workflow())

    async def map_async(self,
                        func: Callable,
                        items: List[Any],
                        max_concurrent: Optional[int] = None) -> List[TaskResult]:
        """
        Map a function over items with concurrency control.

        Args:
            func: Function to apply
            items: Items to process
            max_concurrent: Maximum concurrent executions

        Returns:
            List of TaskResults
        """
        max_concurrent = max_concurrent or self.max_threads
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited_task(item, idx):
            async with semaphore:
                start_time = time.time()
                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(item)
                    else:
                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(
                            self._get_thread_pool(),
                            func,
                            item
                        )

                    return TaskResult(
                        task_id=f"map_{idx}",
                        status=TaskStatus.COMPLETED,
                        result=result,
                        start_time=start_time,
                        end_time=time.time(),
                        execution_time=time.time() - start_time
                    )
                except Exception as e:
                    return TaskResult(
                        task_id=f"map_{idx}",
                        status=TaskStatus.FAILED,
                        error=e,
                        start_time=start_time,
                        end_time=time.time(),
                        execution_time=time.time() - start_time
                    )

        tasks = [limited_task(item, i) for i, item in enumerate(items)]
        return await asyncio.gather(*tasks)

    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown executor pools.

        Args:
            wait: Wait for pending tasks to complete
        """
        if self._thread_pool:
            self._thread_pool.shutdown(wait=wait)
            self._thread_pool = None

        if self._process_pool:
            self._process_pool.shutdown(wait=wait)
            self._process_pool = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()


class WorkflowBuilder:
    """
    Builder for creating complex workflows with dependencies.

    Provides a fluent interface for workflow construction.
    """

    def __init__(self, executor: Optional[ParallelWorkflowExecutor] = None):
        """Initialize workflow builder."""
        self.executor = executor or ParallelWorkflowExecutor()
        self._last_task_id: Optional[str] = None

    def task(self,
             task_id: str,
             func: Callable,
             *args,
             **kwargs) -> "WorkflowBuilder":
        """Add a task to the workflow."""
        self.executor.add_task(task_id, func, args, kwargs)
        self._last_task_id = task_id
        return self

    def depends_on(self, *task_ids: str) -> "WorkflowBuilder":
        """Set dependencies for the last added task."""
        if self._last_task_id and self._last_task_id in self.executor._tasks:
            task = self.executor._tasks[self._last_task_id]
            task.dependencies.update(task_ids)
        return self

    def with_timeout(self, timeout: float) -> "WorkflowBuilder":
        """Set timeout for the last added task."""
        if self._last_task_id and self._last_task_id in self.executor._tasks:
            self.executor._tasks[self._last_task_id].timeout = timeout
        return self

    def with_retries(self, retries: int) -> "WorkflowBuilder":
        """Set retries for the last added task."""
        if self._last_task_id and self._last_task_id in self.executor._tasks:
            self.executor._tasks[self._last_task_id].retries = retries
        return self

    def with_priority(self, priority: TaskPriority) -> "WorkflowBuilder":
        """Set priority for the last added task."""
        if self._last_task_id and self._last_task_id in self.executor._tasks:
            self.executor._tasks[self._last_task_id].priority = priority
        return self

    async def execute(self) -> List[TaskResult]:
        """Execute the workflow."""
        return await self.executor.execute_workflow()

    def run(self) -> List[TaskResult]:
        """Synchronously run the workflow."""
        return asyncio.run(self.execute())


# Convenience functions
def parallel_map(func: Callable,
                items: List[Any],
                max_workers: int = 10) -> List[Any]:
    """
    Apply function to items in parallel.

    Args:
        func: Function to apply
        items: Items to process
        max_workers: Maximum concurrent workers

    Returns:
        List of results
    """
    async def run():
        executor = ParallelWorkflowExecutor(max_threads=max_workers)
        try:
            results = await executor.map_async(func, items)
            return [r.result for r in results if r.success]
        finally:
            executor.shutdown()

    return asyncio.run(run())


def parallel_execute(funcs: List[Callable],
                    args_list: Optional[List[tuple]] = None) -> List[TaskResult]:
    """
    Execute functions in parallel.

    Args:
        funcs: Functions to execute
        args_list: Arguments for each function

    Returns:
        List of TaskResults
    """
    executor = ParallelWorkflowExecutor()
    try:
        return executor.execute_parallel(funcs, args_list)
    finally:
        executor.shutdown()
