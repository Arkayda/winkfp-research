"""Clean-room cryptographic algorithms reconstructed from KrApi."""
from .symmetric import compute_security_key, compute_security_key_symmetric, use_static_placeholder
from .simple import compute_security_key_simple
from .asymmetric import compute_security_key_asymmetric, compute_security_key_asymmetric_as2, RSA_KEYS
from ..security import generate_msvc_nonce, msvc_rand_after_srand

__all__ = [
    "compute_security_key",
    "compute_security_key_symmetric",
    "use_static_placeholder",
    "compute_security_key_simple",
    "compute_security_key_asymmetric",
    "compute_security_key_asymmetric_as2",
    "RSA_KEYS",
    "generate_msvc_nonce",
    "msvc_rand_after_srand",
]
