"""
HexStrike AI v6.0 - Main Entry Point

Modular CTF Automation Platform with integrated AI capabilities.

Usage:
    python -m hexstrike.main [options]
    python hexstrike/main.py [options]

Options:
    --host HOST        Server host (default: 127.0.0.1)
    --port PORT        Server port (default: 8888)
    --config PATH      Configuration file path
    --debug            Enable debug mode
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, jsonify, request

from hexstrike.config.settings import load_settings, get_settings, Settings
from hexstrike.core.cache import LRUCache
from hexstrike.core.error_handler import UnifiedErrorHandler
from hexstrike.core.executor import ToolExecutor
from hexstrike.core.parallel_executor import ParallelWorkflowExecutor
from hexstrike.intelligence.challenge_classifier import ChallengeClassifier
from hexstrike.api.routes.tools import RouteFactory, STANDARD_TOOL_CONFIGS

# Version info
__version__ = "6.0.0"
__author__ = "HexStrike Team"

logger = logging.getLogger(__name__)


def create_app(config_path: str = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_path: Path to configuration file

    Returns:
        Configured Flask application
    """
    # Load settings
    if config_path:
        settings = load_settings(config_path)
    else:
        settings = get_settings()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.logging.level),
        format=settings.logging.format
    )

    if settings.logging.file:
        file_handler = logging.FileHandler(settings.logging.file)
        file_handler.setFormatter(logging.Formatter(settings.logging.format))
        logging.getLogger().addHandler(file_handler)

    # Create Flask app
    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False

    # Initialize components
    cache = LRUCache(
        max_size=settings.cache.max_size,
        default_ttl=settings.cache.ttl
    )
    error_handler = UnifiedErrorHandler(
        max_retries=settings.execution.max_retries,
        base_delay=settings.execution.retry_base_delay,
        max_delay=settings.execution.retry_max_delay
    )
    tool_executor = ToolExecutor(
        default_timeout=settings.execution.command_timeout,
        error_handler=error_handler
    )
    parallel_executor = ParallelWorkflowExecutor(
        max_threads=settings.execution.parallel_max_threads,
        max_processes=settings.execution.parallel_max_processes
    )
    challenge_classifier = ChallengeClassifier()

    # Store components in app context
    app.config['hexstrike'] = {
        'settings': settings,
        'cache': cache,
        'error_handler': error_handler,
        'tool_executor': tool_executor,
        'parallel_executor': parallel_executor,
        'challenge_classifier': challenge_classifier,
    }

    # Register routes
    register_routes(app, settings, tool_executor, challenge_classifier)

    logger.info(f"HexStrike AI v{__version__} initialized")

    return app


def register_routes(app: Flask,
                   settings: Settings,
                   tool_executor: ToolExecutor,
                   classifier: ChallengeClassifier) -> None:
    """Register all API routes."""

    # Health check
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint."""
        available_tools = tool_executor.get_available_tools()
        return jsonify({
            'status': 'healthy',
            'version': __version__,
            'tools_available': len(available_tools),
            'cache_size': app.config['hexstrike']['cache'].size,
        })

    # Challenge classifier endpoint
    @app.route('/api/intelligence/classify', methods=['POST'])
    def classify_challenge():
        """Classify a CTF challenge."""
        data = request.get_json() or {}

        description = data.get('description', '')
        files = data.get('files', [])
        hints = data.get('hints', [])
        url = data.get('url')

        result = classifier.classify(
            description=description,
            files=files,
            hints=hints,
            url=url
        )

        return jsonify({
            'success': True,
            'result': result.to_dict()
        })

    # RSA Attack endpoint
    @app.route('/api/ctf/rsa-attack', methods=['POST'])
    def rsa_attack():
        """RSA attack endpoint."""
        from hexstrike.ctf.solvers.rsa_solver import RSASolver, RSAParameters

        data = request.get_json() or {}

        # Extract parameters
        try:
            n = int(data.get('n', 0))
            e = int(data.get('e', 65537))
            c = int(data.get('c')) if data.get('c') else None

            if n == 0:
                return jsonify({'success': False, 'error': 'Modulus n is required'}), 400

            params = RSAParameters(n=n, e=e, c=c)
            solver = RSASolver()
            result = solver.auto_attack(params)

            return jsonify({
                'success': result.success,
                'attack_type': result.attack_type.value,
                'message': result.message,
                'p': result.p,
                'q': result.q,
                'd': result.d,
                'plaintext': result.plaintext,
                'plaintext_text': result.get_flag() if result.success else None,
                'execution_time': result.execution_time,
            })

        except Exception as e:
            logger.error(f"RSA attack error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # Format String endpoint
    @app.route('/api/ctf/format-string', methods=['POST'])
    def format_string():
        """Format string payload generator."""
        from hexstrike.ctf.solvers.format_string import FormatStringSolver, Architecture

        data = request.get_json() or {}

        try:
            arch_str = data.get('arch', 'x64').lower()
            arch = Architecture.X64 if arch_str == 'x64' else Architecture.X86

            solver = FormatStringSolver(arch=arch)

            action = data.get('action', 'manual_offset')

            if action == 'manual_offset':
                return jsonify({
                    'success': True,
                    'instructions': solver.find_offset_manual()
                })

            elif action == 'write':
                address = int(data.get('address', 0), 16) if isinstance(data.get('address'), str) else data.get('address', 0)
                value = int(data.get('value', 0), 16) if isinstance(data.get('value'), str) else data.get('value', 0)
                offset = data.get('offset', 6)

                payload = solver.arbitrary_write(address, value, offset)

                return jsonify({
                    'success': True,
                    'payload': payload.payload.hex(),
                    'payload_str': str(payload),
                    'description': payload.description,
                })

            elif action == 'got_overwrite':
                got = int(data.get('got', 0), 16) if isinstance(data.get('got'), str) else data.get('got', 0)
                target = int(data.get('target', 0), 16) if isinstance(data.get('target'), str) else data.get('target', 0)
                offset = data.get('offset', 6)

                payload = solver.got_overwrite(got, target, offset)

                return jsonify({
                    'success': True,
                    'payload': payload.payload.hex(),
                    'payload_str': str(payload),
                    'description': payload.description,
                })

            else:
                return jsonify({'success': False, 'error': f'Unknown action: {action}'}), 400

        except Exception as e:
            logger.error(f"Format string error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # ROP Builder endpoint
    @app.route('/api/ctf/rop-chain', methods=['POST'])
    def rop_chain():
        """ROP chain builder."""
        from hexstrike.ctf.solvers.rop_builder import ROPBuilder, Architecture

        data = request.get_json() or {}

        try:
            arch_str = data.get('arch', 'x64').lower()
            arch = Architecture.X64 if arch_str == 'x64' else Architecture.X86

            builder = ROPBuilder(arch=arch)

            # Add gadgets from request
            gadgets = data.get('gadgets', {})
            for name, addr in gadgets.items():
                addr_int = int(addr, 16) if isinstance(addr, str) else addr
                builder.add_gadget(addr_int, name)

            action = data.get('action', 'ret2libc')

            if action == 'ret2libc':
                system = int(data.get('system', 0), 16) if isinstance(data.get('system'), str) else data.get('system', 0)
                binsh = int(data.get('binsh', 0), 16) if isinstance(data.get('binsh'), str) else data.get('binsh', 0)

                chain = builder.build_ret2libc_chain(system, binsh)

                return jsonify({
                    'success': True,
                    'chain': chain.build().hex(),
                    'length': len(chain),
                    'description': chain.description,
                    'dump': chain.dump(),
                })

            elif action == 'execve':
                binsh = int(data.get('binsh', 0), 16) if isinstance(data.get('binsh'), str) else data.get('binsh', 0)
                builder.binsh_addr = binsh

                chain = builder.build_execve_chain()

                return jsonify({
                    'success': True,
                    'chain': chain.build().hex(),
                    'length': len(chain),
                    'description': chain.description,
                    'dump': chain.dump(),
                })

            else:
                return jsonify({'success': False, 'error': f'Unknown action: {action}'}), 400

        except Exception as e:
            logger.error(f"ROP chain error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # Tool routes via factory
    route_factory = RouteFactory(app)
    route_factory.set_executor(tool_executor)
    route_factory.register_tools(STANDARD_TOOL_CONFIGS)

    # API documentation
    @app.route('/api', methods=['GET'])
    def api_docs():
        """API documentation."""
        return jsonify({
            'version': __version__,
            'endpoints': {
                '/health': 'Health check',
                '/api/intelligence/classify': 'Classify CTF challenge',
                '/api/ctf/rsa-attack': 'RSA attack suite',
                '/api/ctf/format-string': 'Format string exploitation',
                '/api/ctf/rop-chain': 'ROP chain builder',
                '/api/tools/*': 'Tool execution endpoints',
            },
            'tools_registered': list(route_factory.get_registered_routes().keys()),
        })


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"HexStrike AI v{__version__} - CTF Automation Platform"
    )
    parser.add_argument('--host', default='127.0.0.1', help='Server host')
    parser.add_argument('--port', type=int, default=8888, help='Server port')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    args = parser.parse_args()

    # Create app
    app = create_app(args.config)

    # Override settings from command line
    if args.debug:
        app.config['hexstrike']['settings'].server.debug = True
        app.debug = True

    # Start server
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║                    HexStrike AI v{__version__}                      ║
║           AI-Powered CTF Automation Platform                  ║
╠═══════════════════════════════════════════════════════════════╣
║  Server: http://{args.host}:{args.port}                              ║
║  Health: http://{args.host}:{args.port}/health                       ║
║  API Docs: http://{args.host}:{args.port}/api                        ║
╚═══════════════════════════════════════════════════════════════╝
    """)

    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        threaded=True
    )


if __name__ == '__main__':
    main()
