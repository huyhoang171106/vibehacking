"""
RSA Attack Suite for CTF Challenges

Implements multiple RSA attack techniques:
- Wiener's attack (large e, small d)
- Fermat factorization (close primes p, q)
- FactorDB API integration
- Small exponent attack (e=3)
- Hastad's broadcast attack
- Common modulus attack
- Auto-attack selection based on parameters
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Optional, Tuple, List, Dict, Any
from enum import Enum
from fractions import Fraction
import asyncio

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)


class RSAAttackType(Enum):
    """Types of RSA attacks available."""
    WIENER = "wiener"
    FERMAT = "fermat"
    FACTORDB = "factordb"
    SMALL_E = "small_e"
    HASTAD = "hastad"
    COMMON_MODULUS = "common_modulus"
    POLLARD_RHO = "pollard_rho"
    POLLARD_P1 = "pollard_p_minus_1"


@dataclass
class RSAParameters:
    """RSA parameters for attack analysis."""
    n: int  # Modulus
    e: int = 65537  # Public exponent
    c: Optional[int] = None  # Ciphertext
    d: Optional[int] = None  # Private exponent (if known)
    p: Optional[int] = None  # First prime factor
    q: Optional[int] = None  # Second prime factor
    phi: Optional[int] = None  # Euler's totient

    # For Hastad's attack (multiple ciphertexts)
    ciphertexts: List[int] = field(default_factory=list)
    moduli: List[int] = field(default_factory=list)

    def bit_length(self) -> int:
        """Return bit length of modulus."""
        return self.n.bit_length()

    def is_factored(self) -> bool:
        """Check if n has been factored."""
        return self.p is not None and self.q is not None


@dataclass
class RSAAttackResult:
    """Result of an RSA attack attempt."""
    success: bool
    attack_type: RSAAttackType
    message: str

    # Recovered values
    p: Optional[int] = None
    q: Optional[int] = None
    d: Optional[int] = None
    plaintext: Optional[int] = None
    plaintext_bytes: Optional[bytes] = None

    # Metadata
    execution_time: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def get_flag(self, encoding: str = "utf-8") -> Optional[str]:
        """Try to extract flag from plaintext."""
        if self.plaintext_bytes:
            try:
                return self.plaintext_bytes.decode(encoding)
            except UnicodeDecodeError:
                return self.plaintext_bytes.hex()
        elif self.plaintext:
            try:
                length = (self.plaintext.bit_length() + 7) // 8
                return self.plaintext.to_bytes(length, 'big').decode(encoding)
            except (UnicodeDecodeError, OverflowError):
                return hex(self.plaintext)
        return None


class RSASolver:
    """
    Comprehensive RSA attack solver for CTF challenges.

    Automatically selects and executes appropriate attacks based on
    the provided RSA parameters.
    """

    def __init__(self, timeout: int = 60):
        """
        Initialize RSA solver.

        Args:
            timeout: Maximum time in seconds for factorization attempts
        """
        self.timeout = timeout
        self._factordb_cache: Dict[int, Tuple[int, int]] = {}

    def auto_attack(self, params: RSAParameters) -> RSAAttackResult:
        """
        Automatically select and execute the best attack based on parameters.

        Args:
            params: RSA parameters to attack

        Returns:
            RSAAttackResult with recovered values if successful
        """
        import time
        start_time = time.time()

        # Determine which attacks to try based on parameters
        attacks_to_try = self._select_attacks(params)

        for attack_type in attacks_to_try:
            logger.info(f"Trying {attack_type.value} attack...")

            try:
                result = self._execute_attack(attack_type, params)
                if result.success:
                    result.execution_time = time.time() - start_time
                    return result
            except Exception as e:
                logger.warning(f"{attack_type.value} attack failed: {e}")
                continue

        return RSAAttackResult(
            success=False,
            attack_type=RSAAttackType.WIENER,  # Default
            message="All attacks failed",
            execution_time=time.time() - start_time
        )

    def _select_attacks(self, params: RSAParameters) -> List[RSAAttackType]:
        """Select appropriate attacks based on parameters."""
        attacks = []

        # Check for Hastad's attack conditions
        if len(params.ciphertexts) >= params.e and params.e <= 17:
            attacks.append(RSAAttackType.HASTAD)

        # Small e attack (e=3 typically)
        if params.e <= 7 and params.c is not None:
            attacks.append(RSAAttackType.SMALL_E)

        # Wiener's attack - large e relative to n
        if params.e > params.n ** 0.25:
            attacks.insert(0, RSAAttackType.WIENER)
        else:
            attacks.append(RSAAttackType.WIENER)

        # Always try Fermat (fast for close primes)
        attacks.append(RSAAttackType.FERMAT)

        # Try FactorDB lookup
        if HAS_REQUESTS:
            attacks.append(RSAAttackType.FACTORDB)

        # Pollard methods for special cases
        attacks.append(RSAAttackType.POLLARD_RHO)
        attacks.append(RSAAttackType.POLLARD_P1)

        return attacks

    def _execute_attack(self, attack_type: RSAAttackType,
                        params: RSAParameters) -> RSAAttackResult:
        """Execute a specific attack type."""
        attack_methods = {
            RSAAttackType.WIENER: self.wiener_attack,
            RSAAttackType.FERMAT: self.fermat_factorization,
            RSAAttackType.FACTORDB: lambda p: self._sync_factordb_lookup(p),
            RSAAttackType.SMALL_E: self.small_e_attack,
            RSAAttackType.HASTAD: self.hastad_broadcast_attack,
            RSAAttackType.POLLARD_RHO: self.pollard_rho,
            RSAAttackType.POLLARD_P1: self.pollard_p_minus_1,
        }

        method = attack_methods.get(attack_type)
        if method:
            return method(params)

        return RSAAttackResult(
            success=False,
            attack_type=attack_type,
            message=f"Unknown attack type: {attack_type}"
        )

    def wiener_attack(self, params: RSAParameters) -> RSAAttackResult:
        """
        Wiener's attack for RSA with small private exponent d.

        Works when d < (1/3) * n^(1/4)
        Typically exploitable when e is very large relative to n.

        Args:
            params: RSA parameters with n and e

        Returns:
            RSAAttackResult with recovered d if successful
        """
        def continued_fraction(num: int, den: int) -> List[int]:
            """Generate continued fraction expansion."""
            cf = []
            while den:
                q = num // den
                cf.append(q)
                num, den = den, num - q * den
            return cf

        def convergents(cf: List[int]) -> List[Tuple[int, int]]:
            """Generate convergents from continued fraction."""
            convs = []
            h_prev, h_curr = 0, 1
            k_prev, k_curr = 1, 0

            for a in cf:
                h_next = a * h_curr + h_prev
                k_next = a * k_curr + k_prev
                convs.append((h_next, k_next))
                h_prev, h_curr = h_curr, h_next
                k_prev, k_curr = k_curr, k_next

            return convs

        n, e = params.n, params.e

        # Get continued fraction of e/n
        cf = continued_fraction(e, n)
        convs = convergents(cf)

        for k, d in convs:
            if k == 0:
                continue

            # Check if (e*d - 1) is divisible by k
            if (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k

            # phi(n) = (p-1)(q-1) = n - p - q + 1
            # So p + q = n - phi + 1
            # And p * q = n
            # This gives us a quadratic: x^2 - (n - phi + 1)x + n = 0

            s = n - phi + 1  # p + q
            discriminant = s * s - 4 * n

            if discriminant < 0:
                continue

            sqrt_disc = self._isqrt(discriminant)
            if sqrt_disc * sqrt_disc != discriminant:
                continue

            p = (s + sqrt_disc) // 2
            q = (s - sqrt_disc) // 2

            if p * q == n:
                # Successfully factored!
                plaintext = None
                plaintext_bytes = None

                if params.c is not None:
                    plaintext = pow(params.c, d, n)
                    try:
                        length = (plaintext.bit_length() + 7) // 8
                        plaintext_bytes = plaintext.to_bytes(length, 'big')
                    except (OverflowError, ValueError):
                        pass

                return RSAAttackResult(
                    success=True,
                    attack_type=RSAAttackType.WIENER,
                    message="Wiener's attack successful - small d recovered",
                    p=p,
                    q=q,
                    d=d,
                    plaintext=plaintext,
                    plaintext_bytes=plaintext_bytes,
                    details={"convergent_index": convs.index((k, d))}
                )

        return RSAAttackResult(
            success=False,
            attack_type=RSAAttackType.WIENER,
            message="Wiener's attack failed - d may not be small enough"
        )

    def fermat_factorization(self, params: RSAParameters,
                            max_iterations: int = 1000000) -> RSAAttackResult:
        """
        Fermat's factorization for close prime factors.

        Works when |p - q| is small (primes are close together).

        Args:
            params: RSA parameters with n
            max_iterations: Maximum iterations to try

        Returns:
            RSAAttackResult with p and q if successful
        """
        n = params.n

        # Start with a = ceil(sqrt(n))
        a = self._isqrt(n)
        if a * a < n:
            a += 1

        b2 = a * a - n

        for _ in range(max_iterations):
            b = self._isqrt(b2)

            if b * b == b2:
                # Found factors
                p = a + b
                q = a - b

                if p * q == n and p > 1 and q > 1:
                    d = None
                    plaintext = None
                    plaintext_bytes = None

                    # Calculate private key
                    phi = (p - 1) * (q - 1)
                    try:
                        d = pow(params.e, -1, phi)

                        if params.c is not None:
                            plaintext = pow(params.c, d, n)
                            try:
                                length = (plaintext.bit_length() + 7) // 8
                                plaintext_bytes = plaintext.to_bytes(length, 'big')
                            except (OverflowError, ValueError):
                                pass
                    except ValueError:
                        pass

                    return RSAAttackResult(
                        success=True,
                        attack_type=RSAAttackType.FERMAT,
                        message="Fermat factorization successful - close primes",
                        p=max(p, q),
                        q=min(p, q),
                        d=d,
                        plaintext=plaintext,
                        plaintext_bytes=plaintext_bytes
                    )

            a += 1
            b2 = a * a - n

        return RSAAttackResult(
            success=False,
            attack_type=RSAAttackType.FERMAT,
            message="Fermat factorization failed - primes not close enough"
        )

    async def factordb_lookup(self, params: RSAParameters) -> RSAAttackResult:
        """
        Look up n in FactorDB for known factorizations.

        Args:
            params: RSA parameters with n

        Returns:
            RSAAttackResult with factors if found in database
        """
        if not HAS_REQUESTS:
            return RSAAttackResult(
                success=False,
                attack_type=RSAAttackType.FACTORDB,
                message="requests library not available"
            )

        n = params.n

        # Check cache first
        if n in self._factordb_cache:
            p, q = self._factordb_cache[n]
            return self._build_factordb_result(params, p, q)

        try:
            url = f"http://factordb.com/api?query={n}"
            response = requests.get(url, timeout=10)
            data = response.json()

            status = data.get("status", "")
            factors = data.get("factors", [])

            # Status codes: 'FF' = fully factored, 'CF' = composite, fully factored
            if status in ("FF", "CF") and len(factors) >= 2:
                # Extract prime factors
                primes = []
                for factor, count in factors:
                    factor = int(factor)
                    primes.extend([factor] * int(count))

                if len(primes) == 2:
                    p, q = primes[0], primes[1]
                    self._factordb_cache[n] = (p, q)
                    return self._build_factordb_result(params, p, q)

            return RSAAttackResult(
                success=False,
                attack_type=RSAAttackType.FACTORDB,
                message=f"FactorDB status: {status} - not fully factored",
                details={"status": status, "factors": factors}
            )

        except Exception as e:
            return RSAAttackResult(
                success=False,
                attack_type=RSAAttackType.FACTORDB,
                message=f"FactorDB lookup failed: {e}"
            )

    def _sync_factordb_lookup(self, params: RSAParameters) -> RSAAttackResult:
        """Synchronous wrapper for factordb_lookup."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.factordb_lookup(params))

    def _build_factordb_result(self, params: RSAParameters,
                               p: int, q: int) -> RSAAttackResult:
        """Build result from FactorDB factors."""
        d = None
        plaintext = None
        plaintext_bytes = None

        phi = (p - 1) * (q - 1)
        try:
            d = pow(params.e, -1, phi)

            if params.c is not None:
                plaintext = pow(params.c, d, params.n)
                try:
                    length = (plaintext.bit_length() + 7) // 8
                    plaintext_bytes = plaintext.to_bytes(length, 'big')
                except (OverflowError, ValueError):
                    pass
        except ValueError:
            pass

        return RSAAttackResult(
            success=True,
            attack_type=RSAAttackType.FACTORDB,
            message="Factors found in FactorDB",
            p=max(p, q),
            q=min(p, q),
            d=d,
            plaintext=plaintext,
            plaintext_bytes=plaintext_bytes
        )

    def small_e_attack(self, params: RSAParameters) -> RSAAttackResult:
        """
        Attack RSA with small public exponent (typically e=3).

        If m^e < n, then c = m^e (no modular reduction occurred).
        Simply compute e-th root of c to recover m.

        Args:
            params: RSA parameters with small e and ciphertext c

        Returns:
            RSAAttackResult with plaintext if successful
        """
        if params.c is None:
            return RSAAttackResult(
                success=False,
                attack_type=RSAAttackType.SMALL_E,
                message="No ciphertext provided"
            )

        e = params.e
        c = params.c

        # Try direct e-th root
        plaintext = self._integer_nth_root(c, e)

        if plaintext ** e == c:
            try:
                length = (plaintext.bit_length() + 7) // 8
                plaintext_bytes = plaintext.to_bytes(length, 'big')
            except (OverflowError, ValueError):
                plaintext_bytes = None

            return RSAAttackResult(
                success=True,
                attack_type=RSAAttackType.SMALL_E,
                message=f"Small e attack successful - m^{e} < n",
                plaintext=plaintext,
                plaintext_bytes=plaintext_bytes
            )

        # Try with small k values: c + k*n might be a perfect e-th power
        for k in range(100):
            candidate = c + k * params.n
            root = self._integer_nth_root(candidate, e)

            if root ** e == candidate:
                try:
                    length = (root.bit_length() + 7) // 8
                    plaintext_bytes = root.to_bytes(length, 'big')
                except (OverflowError, ValueError):
                    plaintext_bytes = None

                return RSAAttackResult(
                    success=True,
                    attack_type=RSAAttackType.SMALL_E,
                    message=f"Small e attack successful with k={k}",
                    plaintext=root,
                    plaintext_bytes=plaintext_bytes,
                    details={"k": k}
                )

        return RSAAttackResult(
            success=False,
            attack_type=RSAAttackType.SMALL_E,
            message="Small e attack failed - message may be padded"
        )

    def hastad_broadcast_attack(self, params: RSAParameters) -> RSAAttackResult:
        """
        Hastad's broadcast attack for same message encrypted with different n.

        If the same message m is encrypted with e different public keys
        (all with the same small e), CRT can recover m.

        Args:
            params: RSA parameters with ciphertexts and moduli lists

        Returns:
            RSAAttackResult with plaintext if successful
        """
        e = params.e
        ciphertexts = params.ciphertexts
        moduli = params.moduli

        if len(ciphertexts) < e or len(moduli) < e:
            return RSAAttackResult(
                success=False,
                attack_type=RSAAttackType.HASTAD,
                message=f"Need at least {e} ciphertext/modulus pairs for e={e}"
            )

        # Take first e pairs
        ciphertexts = ciphertexts[:e]
        moduli = moduli[:e]

        # Use Chinese Remainder Theorem
        result = self._chinese_remainder_theorem(ciphertexts, moduli)

        if result is None:
            return RSAAttackResult(
                success=False,
                attack_type=RSAAttackType.HASTAD,
                message="CRT computation failed - moduli may not be coprime"
            )

        # Result should be m^e, take e-th root
        plaintext = self._integer_nth_root(result, e)

        if plaintext ** e == result:
            try:
                length = (plaintext.bit_length() + 7) // 8
                plaintext_bytes = plaintext.to_bytes(length, 'big')
            except (OverflowError, ValueError):
                plaintext_bytes = None

            return RSAAttackResult(
                success=True,
                attack_type=RSAAttackType.HASTAD,
                message="Hastad broadcast attack successful",
                plaintext=plaintext,
                plaintext_bytes=plaintext_bytes
            )

        return RSAAttackResult(
            success=False,
            attack_type=RSAAttackType.HASTAD,
            message="Hastad attack failed - e-th root not exact"
        )

    def pollard_rho(self, params: RSAParameters,
                    max_iterations: int = 1000000) -> RSAAttackResult:
        """
        Pollard's rho algorithm for factorization.

        Probabilistic algorithm that works well for n with small factors.

        Args:
            params: RSA parameters with n
            max_iterations: Maximum iterations

        Returns:
            RSAAttackResult with factors if found
        """
        n = params.n

        if n % 2 == 0:
            return self._build_factor_result(params, 2, n // 2, RSAAttackType.POLLARD_RHO)

        x = 2
        y = 2
        d = 1

        # f(x) = x^2 + 1 mod n
        f = lambda x: (x * x + 1) % n

        iterations = 0
        while d == 1 and iterations < max_iterations:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
            iterations += 1

        if d != 1 and d != n:
            p, q = d, n // d
            return self._build_factor_result(params, p, q, RSAAttackType.POLLARD_RHO)

        return RSAAttackResult(
            success=False,
            attack_type=RSAAttackType.POLLARD_RHO,
            message="Pollard's rho failed to find factors"
        )

    def pollard_p_minus_1(self, params: RSAParameters,
                          B: int = 100000) -> RSAAttackResult:
        """
        Pollard's p-1 algorithm for factorization.

        Works when p-1 is B-smooth (all prime factors <= B).

        Args:
            params: RSA parameters with n
            B: Smoothness bound

        Returns:
            RSAAttackResult with factors if found
        """
        n = params.n
        a = 2

        # Compute a^(B!) mod n using small primes
        for p in self._primes_up_to(B):
            pp = p
            while pp <= B:
                a = pow(a, p, n)
                pp *= p

        d = math.gcd(a - 1, n)

        if 1 < d < n:
            p, q = d, n // d
            return self._build_factor_result(params, p, q, RSAAttackType.POLLARD_P1)

        return RSAAttackResult(
            success=False,
            attack_type=RSAAttackType.POLLARD_P1,
            message=f"Pollard's p-1 failed with B={B}"
        )

    def common_modulus_attack(self, n: int, e1: int, e2: int,
                              c1: int, c2: int) -> RSAAttackResult:
        """
        Common modulus attack when same message encrypted with different e.

        If gcd(e1, e2) = 1, we can recover m without factoring n.

        Args:
            n: Common modulus
            e1, e2: Two different public exponents
            c1, c2: Corresponding ciphertexts

        Returns:
            RSAAttackResult with plaintext
        """
        # Extended Euclidean algorithm to find s1, s2 such that e1*s1 + e2*s2 = 1
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y

        gcd, s1, s2 = extended_gcd(e1, e2)

        if gcd != 1:
            return RSAAttackResult(
                success=False,
                attack_type=RSAAttackType.COMMON_MODULUS,
                message=f"gcd(e1, e2) = {gcd} != 1"
            )

        # Compute m = c1^s1 * c2^s2 mod n
        # Handle negative exponents by using modular inverse
        if s1 < 0:
            c1 = pow(c1, -1, n)
            s1 = -s1
        if s2 < 0:
            c2 = pow(c2, -1, n)
            s2 = -s2

        plaintext = (pow(c1, s1, n) * pow(c2, s2, n)) % n

        try:
            length = (plaintext.bit_length() + 7) // 8
            plaintext_bytes = plaintext.to_bytes(length, 'big')
        except (OverflowError, ValueError):
            plaintext_bytes = None

        return RSAAttackResult(
            success=True,
            attack_type=RSAAttackType.COMMON_MODULUS,
            message="Common modulus attack successful",
            plaintext=plaintext,
            plaintext_bytes=plaintext_bytes
        )

    def _build_factor_result(self, params: RSAParameters,
                            p: int, q: int,
                            attack_type: RSAAttackType) -> RSAAttackResult:
        """Build a result from found factors."""
        d = None
        plaintext = None
        plaintext_bytes = None

        phi = (p - 1) * (q - 1)
        try:
            d = pow(params.e, -1, phi)

            if params.c is not None:
                plaintext = pow(params.c, d, params.n)
                try:
                    length = (plaintext.bit_length() + 7) // 8
                    plaintext_bytes = plaintext.to_bytes(length, 'big')
                except (OverflowError, ValueError):
                    pass
        except ValueError:
            pass

        return RSAAttackResult(
            success=True,
            attack_type=attack_type,
            message=f"{attack_type.value} attack successful",
            p=max(p, q),
            q=min(p, q),
            d=d,
            plaintext=plaintext,
            plaintext_bytes=plaintext_bytes
        )

    @staticmethod
    def _isqrt(n: int) -> int:
        """Integer square root using Newton's method."""
        if n < 0:
            raise ValueError("Square root of negative number")
        if n == 0:
            return 0

        x = n
        y = (x + 1) // 2
        while y < x:
            x = y
            y = (x + n // x) // 2
        return x

    @staticmethod
    def _integer_nth_root(x: int, n: int) -> int:
        """Compute integer n-th root of x."""
        if x < 0:
            raise ValueError("Cannot compute root of negative number")
        if x == 0:
            return 0
        if n == 1:
            return x

        # Initial guess using floating point
        guess = int(x ** (1/n))

        # Newton-Raphson refinement
        while True:
            next_guess = ((n - 1) * guess + x // (guess ** (n - 1))) // n
            if abs(next_guess - guess) <= 1:
                # Check both guess and guess+1
                if guess ** n == x:
                    return guess
                if (guess + 1) ** n == x:
                    return guess + 1
                # Return closest
                if (guess + 1) ** n <= x:
                    return guess + 1
                return guess
            guess = next_guess

    @staticmethod
    def _chinese_remainder_theorem(remainders: List[int],
                                   moduli: List[int]) -> Optional[int]:
        """
        Chinese Remainder Theorem to solve system of congruences.

        Args:
            remainders: List of remainders
            moduli: List of moduli (must be pairwise coprime)

        Returns:
            x such that x ≡ remainders[i] (mod moduli[i]) for all i
        """
        if len(remainders) != len(moduli):
            return None

        # Compute product of all moduli
        M = 1
        for m in moduli:
            M *= m

        result = 0
        for r, m in zip(remainders, moduli):
            Mi = M // m
            # Find modular inverse of Mi mod m
            try:
                yi = pow(Mi, -1, m)
            except ValueError:
                return None
            result += r * Mi * yi

        return result % M

    @staticmethod
    def _primes_up_to(n: int) -> List[int]:
        """Generate all primes up to n using Sieve of Eratosthenes."""
        if n < 2:
            return []

        sieve = [True] * (n + 1)
        sieve[0] = sieve[1] = False

        for i in range(2, int(n ** 0.5) + 1):
            if sieve[i]:
                for j in range(i * i, n + 1, i):
                    sieve[j] = False

        return [i for i in range(n + 1) if sieve[i]]


# Convenience functions for quick attacks
def attack_rsa(n: int, e: int = 65537, c: Optional[int] = None,
               **kwargs) -> RSAAttackResult:
    """
    Quick function to attack RSA with given parameters.

    Args:
        n: RSA modulus
        e: Public exponent
        c: Ciphertext (optional)
        **kwargs: Additional parameters

    Returns:
        RSAAttackResult
    """
    solver = RSASolver()
    params = RSAParameters(n=n, e=e, c=c, **kwargs)
    return solver.auto_attack(params)


def wiener(n: int, e: int, c: Optional[int] = None) -> RSAAttackResult:
    """Quick Wiener's attack."""
    solver = RSASolver()
    return solver.wiener_attack(RSAParameters(n=n, e=e, c=c))


def fermat(n: int, e: int = 65537, c: Optional[int] = None) -> RSAAttackResult:
    """Quick Fermat factorization."""
    solver = RSASolver()
    return solver.fermat_factorization(RSAParameters(n=n, e=e, c=c))
