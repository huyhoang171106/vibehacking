"""
Consolidated API Route Factory for HexStrike AI

Provides a generic factory pattern for creating tool endpoints
instead of copy-paste route handlers.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Type
from functools import wraps

logger = logging.getLogger(__name__)


@dataclass
class ToolEndpointConfig:
    """Configuration for a tool endpoint."""
    name: str
    route: str
    methods: List[str] = field(default_factory=lambda: ["POST"])
    description: str = ""
    required_params: List[str] = field(default_factory=list)
    optional_params: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 300
    requires_target: bool = True
    validator: Optional[Callable[[Dict], bool]] = None
    executor: Optional[Callable[[Dict], Dict]] = None
    response_transformer: Optional[Callable[[Any], Dict]] = None


class RouteFactory:
    """
    Factory for creating standardized tool API endpoints.

    Reduces code duplication by providing a generic pattern
    for tool route handlers.
    """

    def __init__(self, app=None):
        """
        Initialize route factory.

        Args:
            app: Flask application instance
        """
        self.app = app
        self._registered_routes: Dict[str, ToolEndpointConfig] = {}
        self._tool_executor = None

    def set_app(self, app) -> None:
        """Set the Flask application."""
        self.app = app

    def set_executor(self, executor) -> None:
        """Set the tool executor for running tools."""
        self._tool_executor = executor

    def create_tool_endpoint(self, config: ToolEndpointConfig) -> Callable:
        """
        Create a route handler for a tool endpoint.

        Args:
            config: Tool endpoint configuration

        Returns:
            Route handler function
        """
        def handler():
            from flask import request, jsonify

            start_time = time.time()
            response = {
                "tool": config.name,
                "success": False,
                "timestamp": start_time,
            }

            try:
                # Get request data
                data = request.get_json() or {}

                # Validate required parameters
                missing_params = [
                    p for p in config.required_params
                    if p not in data
                ]
                if missing_params:
                    response["error"] = f"Missing required parameters: {missing_params}"
                    return jsonify(response), 400

                # Apply defaults for optional parameters
                for param, default in config.optional_params.items():
                    if param not in data:
                        data[param] = default

                # Run custom validator if provided
                if config.validator:
                    if not config.validator(data):
                        response["error"] = "Validation failed"
                        return jsonify(response), 400

                # Execute tool
                if config.executor:
                    result = config.executor(data)
                elif self._tool_executor:
                    result = self._execute_tool(config, data)
                else:
                    response["error"] = "No executor configured"
                    return jsonify(response), 500

                # Transform response if needed
                if config.response_transformer:
                    result = config.response_transformer(result)

                response["success"] = True
                response["result"] = result
                response["execution_time"] = time.time() - start_time

                return jsonify(response), 200

            except Exception as e:
                logger.error(f"Error in {config.name} endpoint: {e}")
                response["error"] = str(e)
                response["execution_time"] = time.time() - start_time
                return jsonify(response), 500

        handler.__name__ = f"{config.name}_endpoint"
        handler.__doc__ = config.description

        return handler

    def _execute_tool(self, config: ToolEndpointConfig, data: Dict) -> Any:
        """Execute a tool using the configured executor."""
        if not self._tool_executor:
            raise RuntimeError("No tool executor configured")

        target = data.get("target", "")
        options = data.get("options", {})

        # Build command based on tool configuration
        result = self._tool_executor.execute(
            tool_name=config.name,
            command=self._build_command(config, data),
            timeout=config.timeout
        )

        return {
            "status": result.status.value,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.return_code,
            "execution_time": result.execution_time,
            "parsed": result.parsed_output,
        }

    def _build_command(self, config: ToolEndpointConfig, data: Dict) -> List[str]:
        """Build command from configuration and data."""
        cmd = [config.name]

        if config.requires_target and "target" in data:
            cmd.append(data["target"])

        # Add options
        options = data.get("options", {})
        for key, value in options.items():
            if value is True:
                cmd.append(f"--{key}")
            elif value is not False and value is not None:
                cmd.extend([f"--{key}", str(value)])

        return cmd

    def register(self, config: ToolEndpointConfig) -> None:
        """
        Register a tool endpoint with the application.

        Args:
            config: Tool endpoint configuration
        """
        if not self.app:
            raise RuntimeError("Flask app not set")

        handler = self.create_tool_endpoint(config)
        self.app.add_url_rule(
            config.route,
            endpoint=f"{config.name}_endpoint",
            view_func=handler,
            methods=config.methods
        )

        self._registered_routes[config.name] = config
        logger.info(f"Registered route: {config.route} for {config.name}")

    def register_tools(self, tools: List[ToolEndpointConfig]) -> None:
        """Register multiple tool endpoints."""
        for tool_config in tools:
            self.register(tool_config)

    def get_registered_routes(self) -> Dict[str, ToolEndpointConfig]:
        """Get all registered routes."""
        return self._registered_routes.copy()


# Pre-defined tool configurations
STANDARD_TOOL_CONFIGS = [
    ToolEndpointConfig(
        name="nmap",
        route="/api/tools/nmap",
        description="Network scanner",
        required_params=["target"],
        optional_params={
            "ports": None,
            "scan_type": "-sV",
            "timing": "-T4",
        },
        timeout=600,
    ),
    ToolEndpointConfig(
        name="sqlmap",
        route="/api/tools/sqlmap",
        description="SQL injection testing",
        required_params=["url"],
        optional_params={
            "data": None,
            "level": 1,
            "risk": 1,
            "batch": True,
        },
        timeout=1800,
        requires_target=False,
    ),
    ToolEndpointConfig(
        name="gobuster",
        route="/api/tools/gobuster",
        description="Directory/file brute-force",
        required_params=["url", "wordlist"],
        optional_params={
            "mode": "dir",
            "threads": 10,
            "extensions": "",
        },
        timeout=600,
        requires_target=False,
    ),
    ToolEndpointConfig(
        name="ffuf",
        route="/api/tools/ffuf",
        description="Fast web fuzzer",
        required_params=["url"],
        optional_params={
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "threads": 40,
            "match_codes": "200,204,301,302,307,401,403",
        },
        timeout=600,
        requires_target=False,
    ),
    ToolEndpointConfig(
        name="nuclei",
        route="/api/tools/nuclei",
        description="Vulnerability scanner",
        required_params=["target"],
        optional_params={
            "templates": None,
            "severity": None,
            "rate_limit": 150,
        },
        timeout=900,
    ),
    ToolEndpointConfig(
        name="nikto",
        route="/api/tools/nikto",
        description="Web server scanner",
        required_params=["target"],
        optional_params={
            "tuning": None,
            "plugins": None,
        },
        timeout=1200,
    ),
    ToolEndpointConfig(
        name="hydra",
        route="/api/tools/hydra",
        description="Password brute-force",
        required_params=["target", "service"],
        optional_params={
            "username": None,
            "password_list": None,
            "threads": 16,
        },
        timeout=1800,
    ),
    ToolEndpointConfig(
        name="strings",
        route="/api/tools/strings",
        description="Extract strings from binary",
        required_params=["file"],
        optional_params={
            "min_length": 4,
            "encoding": "s",
        },
        timeout=60,
        requires_target=False,
    ),
    ToolEndpointConfig(
        name="binwalk",
        route="/api/tools/binwalk",
        description="Firmware analysis",
        required_params=["file"],
        optional_params={
            "extract": False,
            "signature": True,
        },
        timeout=300,
        requires_target=False,
    ),
    ToolEndpointConfig(
        name="exiftool",
        route="/api/tools/exiftool",
        description="Metadata extraction",
        required_params=["file"],
        optional_params={},
        timeout=60,
        requires_target=False,
    ),
]


def create_tool_endpoint(name: str,
                        route: str,
                        required_params: List[str] = None,
                        optional_params: Dict[str, Any] = None,
                        timeout: int = 300,
                        **kwargs) -> ToolEndpointConfig:
    """
    Convenience function to create a tool endpoint configuration.

    Args:
        name: Tool name
        route: API route
        required_params: Required parameters
        optional_params: Optional parameters with defaults
        timeout: Execution timeout
        **kwargs: Additional configuration

    Returns:
        ToolEndpointConfig
    """
    return ToolEndpointConfig(
        name=name,
        route=route,
        required_params=required_params or [],
        optional_params=optional_params or {},
        timeout=timeout,
        **kwargs
    )


def register_routes(app, executor=None) -> RouteFactory:
    """
    Register all standard tool routes with the application.

    Args:
        app: Flask application
        executor: Tool executor instance

    Returns:
        RouteFactory instance
    """
    factory = RouteFactory(app)

    if executor:
        factory.set_executor(executor)

    factory.register_tools(STANDARD_TOOL_CONFIGS)

    return factory


# Decorator for creating custom endpoints
def tool_endpoint(name: str,
                 required_params: List[str] = None,
                 optional_params: Dict[str, Any] = None,
                 timeout: int = 300):
    """
    Decorator to mark a function as a tool endpoint handler.

    Usage:
        @tool_endpoint("custom_tool", required_params=["target"])
        def custom_tool_handler(data):
            return {"result": "success"}

    Args:
        name: Tool name
        required_params: Required parameters
        optional_params: Optional parameters with defaults
        timeout: Execution timeout
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        # Attach configuration to function for later registration
        wrapper._tool_config = ToolEndpointConfig(
            name=name,
            route=f"/api/tools/{name}",
            required_params=required_params or [],
            optional_params=optional_params or {},
            timeout=timeout,
            executor=func,
        )

        return wrapper
    return decorator
