"""
Tool Executor Abstraction for HexStrike AI

Unified interface for executing security tools with:
- Standardized execution flow
- Timeout management
- Output parsing
- Error handling integration
"""

import subprocess
import shlex
import time
import signal
import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Union
from enum import Enum
from pathlib import Path

from hexstrike.core.error_handler import UnifiedErrorHandler, ErrorContext, ErrorType

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Status of tool execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    CANCELLED = "cancelled"


@dataclass
class ExecutionResult:
    """Result of a tool execution."""
    status: ExecutionStatus
    tool_name: str
    command: str
    return_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    execution_time: float = 0.0
    parsed_output: Optional[Any] = None
    error_context: Optional[ErrorContext] = None

    @property
    def success(self) -> bool:
        """Check if execution was successful."""
        return self.status == ExecutionStatus.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "tool_name": self.tool_name,
            "command": self.command,
            "return_code": self.return_code,
            "stdout": self.stdout[:1000] if len(self.stdout) > 1000 else self.stdout,
            "stderr": self.stderr[:500] if len(self.stderr) > 500 else self.stderr,
            "execution_time": round(self.execution_time, 3),
            "parsed_output": self.parsed_output,
        }


@dataclass
class ToolConfig:
    """Configuration for a security tool."""
    name: str
    executable: str
    default_timeout: int = 300
    requires_root: bool = False
    output_parser: Optional[Callable[[str], Any]] = None
    success_codes: List[int] = field(default_factory=lambda: [0])
    working_directory: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)


class ToolExecutor:
    """
    Unified tool executor for security tools.

    Provides:
    - Consistent execution interface
    - Timeout management
    - Output parsing
    - Error handling
    - Tool availability checking
    """

    # Common security tool configurations
    TOOL_CONFIGS: Dict[str, ToolConfig] = {
        "nmap": ToolConfig(
            name="nmap",
            executable="nmap",
            default_timeout=600,
            success_codes=[0],
        ),
        "sqlmap": ToolConfig(
            name="sqlmap",
            executable="sqlmap",
            default_timeout=1800,
            success_codes=[0],
        ),
        "nikto": ToolConfig(
            name="nikto",
            executable="nikto",
            default_timeout=1200,
            success_codes=[0],
        ),
        "gobuster": ToolConfig(
            name="gobuster",
            executable="gobuster",
            default_timeout=600,
            success_codes=[0],
        ),
        "ffuf": ToolConfig(
            name="ffuf",
            executable="ffuf",
            default_timeout=600,
            success_codes=[0],
        ),
        "nuclei": ToolConfig(
            name="nuclei",
            executable="nuclei",
            default_timeout=900,
            success_codes=[0],
        ),
        "hydra": ToolConfig(
            name="hydra",
            executable="hydra",
            default_timeout=1800,
            success_codes=[0],
        ),
        "hashcat": ToolConfig(
            name="hashcat",
            executable="hashcat",
            default_timeout=7200,
            success_codes=[0, 1],  # 1 = exhausted search space
        ),
        "john": ToolConfig(
            name="john",
            executable="john",
            default_timeout=3600,
            success_codes=[0],
        ),
        "strings": ToolConfig(
            name="strings",
            executable="strings",
            default_timeout=60,
            success_codes=[0],
        ),
        "binwalk": ToolConfig(
            name="binwalk",
            executable="binwalk",
            default_timeout=300,
            success_codes=[0],
        ),
        "exiftool": ToolConfig(
            name="exiftool",
            executable="exiftool",
            default_timeout=60,
            success_codes=[0],
        ),
        "ROPgadget": ToolConfig(
            name="ROPgadget",
            executable="ROPgadget",
            default_timeout=120,
            success_codes=[0],
        ),
        "checksec": ToolConfig(
            name="checksec",
            executable="checksec",
            default_timeout=30,
            success_codes=[0],
        ),
    }

    def __init__(self,
                 default_timeout: int = 300,
                 error_handler: Optional[UnifiedErrorHandler] = None):
        """
        Initialize tool executor.

        Args:
            default_timeout: Default execution timeout in seconds
            error_handler: Error handler instance
        """
        self.default_timeout = default_timeout
        self.error_handler = error_handler or UnifiedErrorHandler()
        self._tool_cache: Dict[str, bool] = {}
        self._custom_configs: Dict[str, ToolConfig] = {}

    def register_tool(self, config: ToolConfig) -> None:
        """
        Register a custom tool configuration.

        Args:
            config: Tool configuration
        """
        self._custom_configs[config.name] = config

    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """Get configuration for a tool."""
        if tool_name in self._custom_configs:
            return self._custom_configs[tool_name]
        if tool_name in self.TOOL_CONFIGS:
            return self.TOOL_CONFIGS[tool_name]

        # Return default config for unknown tools
        return ToolConfig(
            name=tool_name,
            executable=tool_name,
            default_timeout=self.default_timeout
        )

    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available on the system.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is available
        """
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]

        config = self.get_tool_config(tool_name)
        executable = config.executable

        # Check if executable exists in PATH
        import shutil
        available = shutil.which(executable) is not None

        self._tool_cache[tool_name] = available
        return available

    def execute(self,
                tool_name: str,
                command: Union[str, List[str]],
                timeout: Optional[int] = None,
                working_dir: Optional[str] = None,
                environment: Optional[Dict[str, str]] = None,
                parser: Optional[Callable[[str], Any]] = None,
                capture_stderr: bool = True) -> ExecutionResult:
        """
        Execute a security tool.

        Args:
            tool_name: Name of the tool
            command: Command to execute (string or list)
            timeout: Execution timeout in seconds
            working_dir: Working directory for execution
            environment: Additional environment variables
            parser: Custom output parser
            capture_stderr: Capture stderr in output

        Returns:
            ExecutionResult with execution details
        """
        config = self.get_tool_config(tool_name)

        # Build command
        if isinstance(command, str):
            cmd_list = shlex.split(command)
        else:
            cmd_list = list(command)

        # Check tool availability
        if not self.is_tool_available(tool_name):
            return ExecutionResult(
                status=ExecutionStatus.NOT_FOUND,
                tool_name=tool_name,
                command=" ".join(cmd_list),
                stderr=f"Tool '{tool_name}' not found in PATH",
                error_context=self.error_handler.create_context(
                    message=f"Tool not found: {tool_name}",
                    tool=tool_name
                )
            )

        # Set timeout
        exec_timeout = timeout or config.default_timeout

        # Build environment
        exec_env = os.environ.copy()
        if config.environment:
            exec_env.update(config.environment)
        if environment:
            exec_env.update(environment)

        # Set working directory
        exec_cwd = working_dir or config.working_directory

        # Execute
        start_time = time.time()
        try:
            process = subprocess.Popen(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
                env=exec_env,
                cwd=exec_cwd,
                text=True
            )

            try:
                stdout, stderr = process.communicate(timeout=exec_timeout)
                return_code = process.returncode
                execution_time = time.time() - start_time

                # Determine status
                if return_code in config.success_codes:
                    status = ExecutionStatus.SUCCESS
                else:
                    status = ExecutionStatus.FAILURE

                # Parse output
                parsed_output = None
                output_parser = parser or config.output_parser
                if output_parser and stdout:
                    try:
                        parsed_output = output_parser(stdout)
                    except Exception as e:
                        logger.warning(f"Output parsing failed: {e}")

                return ExecutionResult(
                    status=status,
                    tool_name=tool_name,
                    command=" ".join(cmd_list),
                    return_code=return_code,
                    stdout=stdout or "",
                    stderr=stderr or "",
                    execution_time=execution_time,
                    parsed_output=parsed_output
                )

            except subprocess.TimeoutExpired:
                # Kill the process
                process.kill()
                process.wait()
                execution_time = time.time() - start_time

                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    tool_name=tool_name,
                    command=" ".join(cmd_list),
                    execution_time=execution_time,
                    stderr=f"Execution timed out after {exec_timeout}s",
                    error_context=self.error_handler.create_context(
                        message=f"Tool execution timed out: {tool_name}",
                        tool=tool_name
                    )
                )

        except PermissionError as e:
            return ExecutionResult(
                status=ExecutionStatus.PERMISSION_DENIED,
                tool_name=tool_name,
                command=" ".join(cmd_list),
                execution_time=time.time() - start_time,
                stderr=str(e),
                error_context=self.error_handler.create_context(
                    message=f"Permission denied: {tool_name}",
                    exception=e,
                    tool=tool_name
                )
            )

        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                tool_name=tool_name,
                command=" ".join(cmd_list),
                execution_time=time.time() - start_time,
                stderr=str(e),
                error_context=self.error_handler.create_context(
                    message=f"Execution failed: {e}",
                    exception=e,
                    tool=tool_name
                )
            )

    def execute_with_retry(self,
                          tool_name: str,
                          command: Union[str, List[str]],
                          max_retries: int = 3,
                          **kwargs) -> ExecutionResult:
        """
        Execute tool with automatic retry on failure.

        Args:
            tool_name: Name of the tool
            command: Command to execute
            max_retries: Maximum retry attempts
            **kwargs: Additional arguments for execute()

        Returns:
            ExecutionResult
        """
        last_result = None

        for attempt in range(1, max_retries + 1):
            result = self.execute(tool_name, command, **kwargs)

            if result.success:
                return result

            last_result = result
            logger.warning(f"Attempt {attempt}/{max_retries} failed for {tool_name}")

            # Check if we should retry
            if result.error_context:
                strategy = self.error_handler.get_recovery_strategy(
                    result.error_context.error_type,
                    result.error_context
                )
                from hexstrike.core.error_handler import RecoveryStrategy
                if strategy == RecoveryStrategy.ABORT:
                    break

            if attempt < max_retries:
                # Wait before retry with exponential backoff
                delay = min(2 ** attempt, 30)
                time.sleep(delay)

        return last_result or ExecutionResult(
            status=ExecutionStatus.FAILURE,
            tool_name=tool_name,
            command=str(command),
            stderr="All retry attempts failed"
        )

    def get_available_tools(self) -> List[str]:
        """Get list of available tools."""
        available = []
        all_tools = set(self.TOOL_CONFIGS.keys()) | set(self._custom_configs.keys())

        for tool in all_tools:
            if self.is_tool_available(tool):
                available.append(tool)

        return sorted(available)

    def get_tool_info(self, tool_name: str) -> Dict[str, Any]:
        """Get information about a tool."""
        config = self.get_tool_config(tool_name)
        available = self.is_tool_available(tool_name)

        info = {
            "name": config.name,
            "executable": config.executable,
            "available": available,
            "default_timeout": config.default_timeout,
            "requires_root": config.requires_root,
        }

        if available:
            # Try to get version
            try:
                result = self.execute(tool_name, [config.executable, "--version"], timeout=10)
                if result.stdout:
                    info["version"] = result.stdout.split("\n")[0].strip()
            except Exception:
                pass

        return info


# Output parsers for common tools
def parse_nmap_output(output: str) -> Dict[str, Any]:
    """Parse nmap output into structured data."""
    result = {
        "hosts": [],
        "ports": [],
        "raw": output
    }

    # Simple parsing - for full parsing, use python-nmap
    import re

    # Find open ports
    port_pattern = r"(\d+)/(\w+)\s+open\s+(\S+)"
    for match in re.finditer(port_pattern, output):
        result["ports"].append({
            "port": int(match.group(1)),
            "protocol": match.group(2),
            "service": match.group(3)
        })

    return result


def parse_gobuster_output(output: str) -> Dict[str, Any]:
    """Parse gobuster output."""
    result = {
        "found": [],
        "raw": output
    }

    for line in output.split("\n"):
        if line.strip() and not line.startswith("="):
            # Extract path and status code
            parts = line.split()
            if len(parts) >= 2:
                result["found"].append({
                    "path": parts[0],
                    "status": parts[1] if len(parts) > 1 else None
                })

    return result


def parse_checksec_output(output: str) -> Dict[str, Any]:
    """Parse checksec output."""
    result = {
        "protections": {},
        "raw": output
    }

    protection_patterns = {
        "RELRO": r"RELRO\s*:\s*(\S+)",
        "STACK CANARY": r"Stack\s*:\s*(\S+)",
        "NX": r"NX\s*:\s*(\S+)",
        "PIE": r"PIE\s*:\s*(\S+)",
    }

    import re
    for name, pattern in protection_patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result["protections"][name] = match.group(1)

    return result


# Register parsers with tool configs
ToolExecutor.TOOL_CONFIGS["nmap"].output_parser = parse_nmap_output
ToolExecutor.TOOL_CONFIGS["gobuster"].output_parser = parse_gobuster_output
ToolExecutor.TOOL_CONFIGS["checksec"].output_parser = parse_checksec_output


# Convenience function
def execute_tool(tool_name: str,
                command: Union[str, List[str]],
                timeout: Optional[int] = None) -> ExecutionResult:
    """
    Quick function to execute a tool.

    Args:
        tool_name: Tool name
        command: Command to run
        timeout: Execution timeout

    Returns:
        ExecutionResult
    """
    executor = ToolExecutor()
    return executor.execute(tool_name, command, timeout=timeout)
