"""
Challenge Auto-Classifier for CTF Challenges

Automatically detects challenge category and type from:
- Description keywords and patterns
- File extensions and types
- Binary signatures and magic bytes
- Network patterns and protocols
- Service fingerprints
"""

import re
import os
import struct
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ChallengeCategory(Enum):
    """Main CTF challenge categories."""
    CRYPTO = "crypto"
    PWN = "pwn"
    WEB = "web"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    MISC = "misc"
    OSINT = "osint"
    STEGANOGRAPHY = "steganography"
    MOBILE = "mobile"
    HARDWARE = "hardware"
    BLOCKCHAIN = "blockchain"
    UNKNOWN = "unknown"


class CryptoSubType(Enum):
    """Cryptography challenge subtypes."""
    RSA = "rsa"
    AES = "aes"
    DES = "des"
    XOR = "xor"
    HASH = "hash"
    CLASSICAL = "classical"  # Caesar, Vigenere, etc.
    ECC = "ecc"
    DIFFIE_HELLMAN = "diffie_hellman"
    PADDING_ORACLE = "padding_oracle"
    PRNG = "prng"
    CUSTOM = "custom"


class PwnSubType(Enum):
    """Binary exploitation challenge subtypes."""
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    ROP = "rop"
    HEAP = "heap"
    SHELLCODE = "shellcode"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_AFTER_FREE = "use_after_free"
    KERNEL = "kernel"
    RACE_CONDITION = "race_condition"


class WebSubType(Enum):
    """Web challenge subtypes."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    LFI = "lfi"
    RFI = "rfi"
    COMMAND_INJECTION = "command_injection"
    DESERIALIZATION = "deserialization"
    AUTHENTICATION = "authentication"
    SESSION = "session"
    RACE_CONDITION = "race_condition"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    GRAPHQL = "graphql"
    JWT = "jwt"


@dataclass
class ClassificationResult:
    """Result of challenge classification."""
    category: ChallengeCategory
    confidence: float  # 0.0 to 1.0
    subtype: Optional[str] = None
    recommended_tools: List[str] = field(default_factory=list)
    keywords_matched: List[str] = field(default_factory=list)
    file_indicators: List[str] = field(default_factory=list)
    analysis_notes: List[str] = field(default_factory=list)

    # Secondary categories if applicable
    secondary_categories: List[Tuple[ChallengeCategory, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "confidence": self.confidence,
            "subtype": self.subtype,
            "recommended_tools": self.recommended_tools,
            "keywords_matched": self.keywords_matched,
            "file_indicators": self.file_indicators,
            "analysis_notes": self.analysis_notes,
            "secondary_categories": [
                {"category": cat.value, "confidence": conf}
                for cat, conf in self.secondary_categories
            ]
        }


class ChallengeClassifier:
    """
    Intelligent classifier for CTF challenges.

    Analyzes challenge descriptions, files, and hints to determine
    the category and recommend appropriate tools.
    """

    # Keyword patterns for each category
    CATEGORY_KEYWORDS: Dict[ChallengeCategory, Dict[str, float]] = {
        ChallengeCategory.CRYPTO: {
            # RSA related
            "rsa": 0.9, "modulus": 0.7, "exponent": 0.6, "n=": 0.5,
            "e=": 0.5, "d=": 0.6, "p=": 0.4, "q=": 0.4, "phi": 0.6,
            "factorization": 0.7, "prime": 0.5, "coprime": 0.6,
            # AES/block cipher
            "aes": 0.9, "cbc": 0.8, "ecb": 0.8, "ctr": 0.8, "gcm": 0.8,
            "block cipher": 0.9, "padding": 0.6, "iv": 0.5,
            # General crypto
            "encrypt": 0.7, "decrypt": 0.7, "cipher": 0.8, "ciphertext": 0.9,
            "plaintext": 0.8, "key": 0.4, "secret key": 0.7,
            "public key": 0.8, "private key": 0.8,
            # Hashing
            "hash": 0.6, "md5": 0.8, "sha": 0.7, "sha256": 0.8, "sha1": 0.8,
            "hmac": 0.8, "collision": 0.7, "preimage": 0.8,
            # Classical
            "caesar": 0.9, "vigenere": 0.9, "substitution": 0.7,
            "transposition": 0.8, "rot13": 0.9, "xor": 0.6, "frequency": 0.5,
            # Other
            "diffie": 0.9, "hellman": 0.9, "dh": 0.6, "ecdsa": 0.9,
            "ecc": 0.8, "elliptic": 0.8, "curve": 0.5, "prng": 0.8,
            "random": 0.4, "stream cipher": 0.9, "rc4": 0.9,
        },

        ChallengeCategory.PWN: {
            # Buffer overflow
            "buffer overflow": 0.95, "bof": 0.9, "stack": 0.6, "canary": 0.8,
            "overflow": 0.7, "smash": 0.8, "overwrite": 0.6,
            # Memory corruption
            "memory": 0.4, "heap": 0.8, "malloc": 0.7, "free": 0.5,
            "use after free": 0.95, "uaf": 0.9, "double free": 0.95,
            "arbitrary write": 0.9, "arbitrary read": 0.8,
            # Exploitation techniques
            "rop": 0.9, "gadget": 0.8, "shellcode": 0.9, "shell": 0.5,
            "ret2libc": 0.95, "ret2plt": 0.9, "ret2csu": 0.95,
            "format string": 0.95, "printf": 0.6, "%p": 0.8, "%n": 0.9,
            "got": 0.7, "plt": 0.7, "libc": 0.7,
            # Protections
            "pie": 0.7, "aslr": 0.8, "nx": 0.7, "dep": 0.7, "relro": 0.8,
            # Binary
            "elf": 0.6, "binary": 0.5, "executable": 0.5, "pwn": 0.9,
            "exploit": 0.6, "nc": 0.4, "netcat": 0.5, "pwntools": 0.9,
            # Integer
            "integer overflow": 0.95, "signed": 0.5, "unsigned": 0.5,
        },

        ChallengeCategory.WEB: {
            # Injection
            "sql injection": 0.95, "sqli": 0.95, "sql": 0.6,
            "xss": 0.95, "cross-site": 0.8, "script": 0.4,
            "command injection": 0.95, "rce": 0.8, "os.system": 0.8,
            "ssrf": 0.95, "server-side request": 0.9,
            "xxe": 0.95, "xml": 0.6, "external entity": 0.9,
            "lfi": 0.95, "rfi": 0.9, "include": 0.5, "file inclusion": 0.9,
            "ssti": 0.95, "template injection": 0.95, "jinja": 0.8, "twig": 0.8,
            # Web technologies
            "http": 0.4, "https": 0.4, "url": 0.4, "request": 0.4,
            "response": 0.4, "cookie": 0.6, "session": 0.6, "jwt": 0.8,
            "token": 0.5, "authentication": 0.6, "login": 0.5,
            "api": 0.5, "rest": 0.5, "graphql": 0.8,
            # Languages/frameworks
            "php": 0.6, "python": 0.4, "node": 0.5, "flask": 0.6,
            "django": 0.6, "express": 0.6, "wordpress": 0.7,
            # Other
            "web": 0.5, "website": 0.6, "browser": 0.4, "html": 0.4,
            "javascript": 0.5, "css": 0.3, "dom": 0.5,
            "deserialization": 0.9, "pickle": 0.8, "yaml": 0.5,
            "prototype pollution": 0.95, "__proto__": 0.95,
            "race condition": 0.7, "csrf": 0.9, "cors": 0.7,
        },

        ChallengeCategory.REVERSE: {
            # General RE
            "reverse": 0.8, "reverse engineering": 0.95, "disassemble": 0.9,
            "decompile": 0.9, "assembly": 0.7, "asm": 0.6,
            # Tools
            "ida": 0.8, "ghidra": 0.9, "radare": 0.8, "r2": 0.7,
            "gdb": 0.6, "objdump": 0.7, "strings": 0.4,
            # Binary types
            "elf": 0.5, "pe": 0.6, "exe": 0.6, "dll": 0.6, "so": 0.5,
            "apk": 0.7, "dex": 0.8,
            # Code features
            "function": 0.3, "anti-debug": 0.9, "obfuscation": 0.8,
            "packer": 0.8, "unpacker": 0.8, "upx": 0.8, "vmprotect": 0.9,
            "crackme": 0.95, "keygen": 0.9, "serial": 0.6, "license": 0.5,
            # Architecture
            "x86": 0.6, "x64": 0.6, "arm": 0.6, "mips": 0.7,
        },

        ChallengeCategory.FORENSICS: {
            # General
            "forensics": 0.9, "investigation": 0.6, "analyze": 0.4,
            "evidence": 0.7, "artifact": 0.7,
            # Memory
            "memory dump": 0.95, "volatility": 0.95, "memdump": 0.9,
            "ram": 0.6, "process": 0.4,
            # Disk/File
            "disk image": 0.9, "filesystem": 0.7, "deleted": 0.6,
            "recover": 0.5, "carve": 0.8, "autopsy": 0.9,
            # Network
            "pcap": 0.95, "wireshark": 0.9, "packet": 0.7, "capture": 0.6,
            "network traffic": 0.9, "tcpdump": 0.8,
            # File types
            "pdf": 0.4, "office": 0.5, "document": 0.4,
            "log": 0.5, "registry": 0.7, "event": 0.4,
        },

        ChallengeCategory.STEGANOGRAPHY: {
            "steg": 0.9, "steganography": 0.95, "hidden": 0.6,
            "embed": 0.6, "extract": 0.5, "lsb": 0.9,
            "image": 0.4, "png": 0.4, "jpg": 0.4, "jpeg": 0.4,
            "gif": 0.4, "bmp": 0.4, "pixel": 0.6,
            "audio": 0.4, "wav": 0.5, "mp3": 0.4, "spectrogram": 0.9,
            "steghide": 0.9, "stegsolve": 0.9, "zsteg": 0.9,
            "exif": 0.7, "metadata": 0.6, "binwalk": 0.7,
        },

        ChallengeCategory.OSINT: {
            "osint": 0.95, "open source intelligence": 0.95,
            "geolocation": 0.9, "location": 0.5, "where": 0.3,
            "person": 0.4, "find": 0.3, "identify": 0.4,
            "social media": 0.8, "twitter": 0.6, "linkedin": 0.6,
            "facebook": 0.6, "instagram": 0.6,
            "google": 0.4, "search": 0.3, "dorking": 0.8,
            "shodan": 0.8, "censys": 0.8, "whois": 0.7,
            "photo": 0.4, "image": 0.3, "exif": 0.6,
        },

        ChallengeCategory.MISC: {
            "misc": 0.8, "miscellaneous": 0.8,
            "programming": 0.5, "coding": 0.5, "algorithm": 0.5,
            "ppc": 0.8, "trivia": 0.7, "quiz": 0.6,
            "game": 0.4, "puzzle": 0.5, "riddle": 0.5,
            "jail": 0.7, "escape": 0.5, "sandbox": 0.7,
            "pyjail": 0.9, "python jail": 0.9,
        },

        ChallengeCategory.BLOCKCHAIN: {
            "blockchain": 0.95, "ethereum": 0.9, "solidity": 0.95,
            "smart contract": 0.95, "web3": 0.8, "defi": 0.8,
            "token": 0.5, "nft": 0.7, "transaction": 0.5,
            "wallet": 0.6, "reentrancy": 0.95, "flashloan": 0.9,
        },
    }

    # File extension mappings
    FILE_EXTENSIONS: Dict[str, Tuple[ChallengeCategory, float]] = {
        # Crypto
        ".pem": (ChallengeCategory.CRYPTO, 0.9),
        ".key": (ChallengeCategory.CRYPTO, 0.7),
        ".pub": (ChallengeCategory.CRYPTO, 0.8),
        ".enc": (ChallengeCategory.CRYPTO, 0.8),
        ".crt": (ChallengeCategory.CRYPTO, 0.7),

        # Binary/PWN/Reverse
        ".elf": (ChallengeCategory.PWN, 0.8),
        ".exe": (ChallengeCategory.REVERSE, 0.7),
        ".dll": (ChallengeCategory.REVERSE, 0.7),
        ".so": (ChallengeCategory.PWN, 0.7),
        ".bin": (ChallengeCategory.PWN, 0.6),

        # Web
        ".php": (ChallengeCategory.WEB, 0.8),
        ".html": (ChallengeCategory.WEB, 0.5),
        ".js": (ChallengeCategory.WEB, 0.5),
        ".asp": (ChallengeCategory.WEB, 0.8),
        ".aspx": (ChallengeCategory.WEB, 0.8),
        ".jsp": (ChallengeCategory.WEB, 0.8),

        # Forensics
        ".pcap": (ChallengeCategory.FORENSICS, 0.95),
        ".pcapng": (ChallengeCategory.FORENSICS, 0.95),
        ".raw": (ChallengeCategory.FORENSICS, 0.7),
        ".mem": (ChallengeCategory.FORENSICS, 0.9),
        ".vmem": (ChallengeCategory.FORENSICS, 0.9),
        ".dmp": (ChallengeCategory.FORENSICS, 0.8),
        ".img": (ChallengeCategory.FORENSICS, 0.7),
        ".dd": (ChallengeCategory.FORENSICS, 0.8),
        ".E01": (ChallengeCategory.FORENSICS, 0.9),

        # Steganography
        ".png": (ChallengeCategory.STEGANOGRAPHY, 0.5),
        ".jpg": (ChallengeCategory.STEGANOGRAPHY, 0.5),
        ".jpeg": (ChallengeCategory.STEGANOGRAPHY, 0.5),
        ".gif": (ChallengeCategory.STEGANOGRAPHY, 0.5),
        ".bmp": (ChallengeCategory.STEGANOGRAPHY, 0.5),
        ".wav": (ChallengeCategory.STEGANOGRAPHY, 0.6),

        # Mobile
        ".apk": (ChallengeCategory.MOBILE, 0.9),
        ".ipa": (ChallengeCategory.MOBILE, 0.9),

        # Blockchain
        ".sol": (ChallengeCategory.BLOCKCHAIN, 0.95),
    }

    # Magic bytes for file type detection
    MAGIC_BYTES: Dict[bytes, Tuple[str, ChallengeCategory, float]] = {
        b"\x7fELF": ("ELF binary", ChallengeCategory.PWN, 0.7),
        b"MZ": ("PE executable", ChallengeCategory.REVERSE, 0.7),
        b"\xd4\xc3\xb2\xa1": ("PCAP (little-endian)", ChallengeCategory.FORENSICS, 0.95),
        b"\xa1\xb2\xc3\xd4": ("PCAP (big-endian)", ChallengeCategory.FORENSICS, 0.95),
        b"\x0a\x0d\x0d\x0a": ("PCAPNG", ChallengeCategory.FORENSICS, 0.95),
        b"\x89PNG": ("PNG image", ChallengeCategory.STEGANOGRAPHY, 0.5),
        b"\xff\xd8\xff": ("JPEG image", ChallengeCategory.STEGANOGRAPHY, 0.5),
        b"GIF87a": ("GIF image", ChallengeCategory.STEGANOGRAPHY, 0.5),
        b"GIF89a": ("GIF image", ChallengeCategory.STEGANOGRAPHY, 0.5),
        b"PK\x03\x04": ("ZIP archive", ChallengeCategory.FORENSICS, 0.5),
        b"Rar!\x1a\x07": ("RAR archive", ChallengeCategory.FORENSICS, 0.5),
        b"\x1f\x8b": ("GZIP compressed", ChallengeCategory.FORENSICS, 0.5),
        b"BZh": ("BZIP2 compressed", ChallengeCategory.FORENSICS, 0.5),
        b"RIFF": ("RIFF (WAV/AVI)", ChallengeCategory.STEGANOGRAPHY, 0.6),
        b"%PDF": ("PDF document", ChallengeCategory.FORENSICS, 0.6),
        b"SQLite": ("SQLite database", ChallengeCategory.FORENSICS, 0.7),
    }

    # Tool recommendations by category and subtype
    TOOL_RECOMMENDATIONS: Dict[ChallengeCategory, Dict[str, List[str]]] = {
        ChallengeCategory.CRYPTO: {
            "rsa": ["RsaCtfTool", "rsatool", "factordb", "yafu", "sage"],
            "aes": ["aeskeyfind", "PadBuster", "custom scripts"],
            "hash": ["hashcat", "john", "hash-identifier"],
            "classical": ["CyberChef", "dcode.fr", "quipqiup"],
            "default": ["CyberChef", "python/gmpy2", "sage"],
        },
        ChallengeCategory.PWN: {
            "buffer_overflow": ["pwntools", "gdb", "checksec", "ROPgadget"],
            "format_string": ["pwntools", "gdb", "objdump"],
            "rop": ["ROPgadget", "ropper", "pwntools", "one_gadget"],
            "heap": ["pwntools", "gdb", "heap-viewer", "pwndbg"],
            "default": ["pwntools", "gdb", "checksec", "objdump"],
        },
        ChallengeCategory.WEB: {
            "sql_injection": ["sqlmap", "burpsuite", "manual testing"],
            "xss": ["burpsuite", "dalfox", "manual testing"],
            "ssrf": ["burpsuite", "ssrfmap", "manual testing"],
            "ssti": ["tplmap", "burpsuite", "manual testing"],
            "jwt": ["jwt_tool", "jwt.io", "burpsuite"],
            "default": ["burpsuite", "curl", "browser devtools"],
        },
        ChallengeCategory.REVERSE: {
            "default": ["ghidra", "ida", "radare2", "gdb", "strings"],
        },
        ChallengeCategory.FORENSICS: {
            "memory": ["volatility3", "strings", "foremost"],
            "network": ["wireshark", "tshark", "NetworkMiner"],
            "disk": ["autopsy", "sleuthkit", "foremost", "binwalk"],
            "default": ["binwalk", "strings", "file", "exiftool"],
        },
        ChallengeCategory.STEGANOGRAPHY: {
            "image": ["stegsolve", "zsteg", "steghide", "exiftool", "binwalk"],
            "audio": ["audacity", "sonic-visualiser", "steghide"],
            "default": ["binwalk", "exiftool", "strings", "stegsolve"],
        },
        ChallengeCategory.OSINT: {
            "default": ["google", "shodan", "maltego", "sherlock"],
        },
        ChallengeCategory.MISC: {
            "default": ["python", "CyberChef", "manual analysis"],
        },
        ChallengeCategory.BLOCKCHAIN: {
            "default": ["remix", "foundry", "slither", "mythril"],
        },
    }

    def __init__(self):
        """Initialize the classifier."""
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for better performance."""
        self._keyword_patterns: Dict[ChallengeCategory, Dict[re.Pattern, float]] = {}

        for category, keywords in self.CATEGORY_KEYWORDS.items():
            self._keyword_patterns[category] = {
                re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE): weight
                for kw, weight in keywords.items()
            }

    def classify(self, description: str = "",
                 files: Optional[List[str]] = None,
                 hints: Optional[List[str]] = None,
                 url: Optional[str] = None,
                 port: Optional[int] = None) -> ClassificationResult:
        """
        Classify a CTF challenge based on available information.

        Args:
            description: Challenge description text
            files: List of file paths associated with the challenge
            hints: Any hints provided
            url: Target URL if applicable
            port: Target port if applicable

        Returns:
            ClassificationResult with category, confidence, and recommendations
        """
        files = files or []
        hints = hints or []

        # Combine all text for analysis
        all_text = " ".join([
            description,
            " ".join(hints),
            " ".join(os.path.basename(f) for f in files),
        ]).lower()

        # Score each category
        category_scores: Dict[ChallengeCategory, float] = {
            cat: 0.0 for cat in ChallengeCategory
        }
        keywords_matched: Dict[ChallengeCategory, List[str]] = {
            cat: [] for cat in ChallengeCategory
        }

        # Analyze text for keywords
        for category, patterns in self._keyword_patterns.items():
            for pattern, weight in patterns.items():
                if pattern.search(all_text):
                    category_scores[category] += weight
                    keywords_matched[category].append(pattern.pattern.strip(r"\b"))

        # Analyze files
        file_indicators: List[str] = []
        for file_path in files:
            file_result = self._analyze_file(file_path)
            if file_result:
                cat, score, indicator = file_result
                category_scores[cat] += score
                file_indicators.append(indicator)

        # Check URL patterns
        if url:
            url_result = self._analyze_url(url)
            if url_result:
                category_scores[ChallengeCategory.WEB] += url_result

        # Check port patterns
        if port:
            port_result = self._analyze_port(port)
            if port_result:
                cat, score = port_result
                category_scores[cat] += score

        # Determine winner
        max_score = max(category_scores.values())
        if max_score == 0:
            return ClassificationResult(
                category=ChallengeCategory.UNKNOWN,
                confidence=0.0,
                analysis_notes=["No indicators matched"]
            )

        # Find best category
        best_category = max(category_scores, key=lambda k: category_scores[k])

        # Calculate confidence (normalize score)
        confidence = min(1.0, category_scores[best_category] / 5.0)

        # Detect subtype
        subtype = self._detect_subtype(best_category, all_text, keywords_matched[best_category])

        # Get tool recommendations
        recommended_tools = self._get_tool_recommendations(best_category, subtype)

        # Get secondary categories
        secondary = [
            (cat, min(1.0, score / 5.0))
            for cat, score in sorted(category_scores.items(), key=lambda x: -x[1])
            if cat != best_category and score > 0
        ][:3]

        return ClassificationResult(
            category=best_category,
            confidence=confidence,
            subtype=subtype,
            recommended_tools=recommended_tools,
            keywords_matched=keywords_matched[best_category],
            file_indicators=file_indicators,
            secondary_categories=secondary,
            analysis_notes=self._generate_notes(best_category, subtype, confidence)
        )

    def _analyze_file(self, file_path: str) -> Optional[Tuple[ChallengeCategory, float, str]]:
        """Analyze a file to determine challenge category."""
        # Check extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.FILE_EXTENSIONS:
            cat, score = self.FILE_EXTENSIONS[ext]
            return cat, score, f"File extension: {ext}"

        # Check magic bytes if file exists
        if os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    header = f.read(16)

                for magic, (desc, cat, score) in self.MAGIC_BYTES.items():
                    if header.startswith(magic):
                        return cat, score, f"Magic bytes: {desc}"

                # Check for ELF with more analysis
                if header.startswith(b"\x7fELF"):
                    # Check if it's stripped, has symbols, etc.
                    return ChallengeCategory.PWN, 0.7, "ELF binary detected"

            except (IOError, PermissionError):
                pass

        return None

    def _analyze_url(self, url: str) -> float:
        """Analyze URL to boost web category score."""
        url_lower = url.lower()
        score = 0.5  # Base score for having a URL

        # Check for interesting patterns
        if "api" in url_lower:
            score += 0.2
        if "login" in url_lower or "admin" in url_lower:
            score += 0.3
        if ".php" in url_lower:
            score += 0.2
        if "?" in url_lower:  # Has parameters
            score += 0.2

        return score

    def _analyze_port(self, port: int) -> Optional[Tuple[ChallengeCategory, float]]:
        """Analyze port number to determine likely category."""
        port_mappings = {
            # Web ports
            80: (ChallengeCategory.WEB, 0.5),
            443: (ChallengeCategory.WEB, 0.5),
            8080: (ChallengeCategory.WEB, 0.5),
            8000: (ChallengeCategory.WEB, 0.5),
            3000: (ChallengeCategory.WEB, 0.5),
            # PWN ports (custom high ports often used)
            # No specific mapping, but 1024+ could be pwn
        }

        if port in port_mappings:
            return port_mappings[port]

        # High ports often used for pwn challenges
        if port > 1024 and port < 65535:
            return ChallengeCategory.PWN, 0.3

        return None

    def _detect_subtype(self, category: ChallengeCategory,
                        text: str, matched_keywords: List[str]) -> Optional[str]:
        """Detect specific subtype within a category."""
        text_lower = text.lower()
        matched_set = set(kw.lower() for kw in matched_keywords)

        if category == ChallengeCategory.CRYPTO:
            if any(kw in matched_set for kw in ["rsa", "modulus", "exponent", "factorization"]):
                return CryptoSubType.RSA.value
            if any(kw in matched_set for kw in ["aes", "cbc", "ecb", "block cipher"]):
                return CryptoSubType.AES.value
            if any(kw in matched_set for kw in ["xor"]):
                return CryptoSubType.XOR.value
            if any(kw in matched_set for kw in ["caesar", "vigenere", "substitution", "rot13"]):
                return CryptoSubType.CLASSICAL.value
            if any(kw in matched_set for kw in ["hash", "md5", "sha"]):
                return CryptoSubType.HASH.value

        elif category == ChallengeCategory.PWN:
            if "format string" in text_lower or "%n" in text_lower:
                return PwnSubType.FORMAT_STRING.value
            if "rop" in matched_set or "gadget" in matched_set:
                return PwnSubType.ROP.value
            if "heap" in matched_set or "malloc" in matched_set:
                return PwnSubType.HEAP.value
            if "buffer overflow" in text_lower or "bof" in matched_set:
                return PwnSubType.BUFFER_OVERFLOW.value
            if "shellcode" in matched_set:
                return PwnSubType.SHELLCODE.value

        elif category == ChallengeCategory.WEB:
            if "sql" in matched_set or "sqli" in matched_set:
                return WebSubType.SQL_INJECTION.value
            if "xss" in matched_set or "cross-site" in matched_set:
                return WebSubType.XSS.value
            if "ssrf" in matched_set:
                return WebSubType.SSRF.value
            if "ssti" in matched_set or "template" in text_lower:
                return WebSubType.SSTI.value
            if "jwt" in matched_set:
                return WebSubType.JWT.value
            if "xxe" in matched_set or "xml" in matched_set:
                return WebSubType.XXE.value

        return None

    def _get_tool_recommendations(self, category: ChallengeCategory,
                                  subtype: Optional[str]) -> List[str]:
        """Get recommended tools for the category and subtype."""
        if category not in self.TOOL_RECOMMENDATIONS:
            return []

        tools = self.TOOL_RECOMMENDATIONS[category]

        if subtype and subtype in tools:
            return tools[subtype]

        return tools.get("default", [])

    def _generate_notes(self, category: ChallengeCategory,
                        subtype: Optional[str],
                        confidence: float) -> List[str]:
        """Generate analysis notes."""
        notes = []

        if confidence < 0.3:
            notes.append("Low confidence - consider manual analysis")
        elif confidence < 0.6:
            notes.append("Medium confidence - verify category before proceeding")

        if subtype:
            notes.append(f"Specific attack type identified: {subtype}")

        return notes

    def classify_from_files(self, file_paths: List[str]) -> ClassificationResult:
        """
        Classify challenge based only on provided files.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            ClassificationResult
        """
        return self.classify(files=file_paths)

    def classify_from_description(self, description: str) -> ClassificationResult:
        """
        Classify challenge based only on description.

        Args:
            description: Challenge description text

        Returns:
            ClassificationResult
        """
        return self.classify(description=description)


# Convenience function
def classify_challenge(description: str = "",
                      files: Optional[List[str]] = None,
                      hints: Optional[List[str]] = None,
                      url: Optional[str] = None) -> ClassificationResult:
    """
    Quick function to classify a CTF challenge.

    Args:
        description: Challenge description
        files: Associated files
        hints: Hints provided
        url: Target URL

    Returns:
        ClassificationResult
    """
    classifier = ChallengeClassifier()
    return classifier.classify(description, files, hints, url)
