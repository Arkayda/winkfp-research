"""GetAuthKey resolution layer."""
from ...as2_keys import As2KeyStore

def resolve_auth_key(store: As2KeyStore, ecu_name: str, index: int) -> bytes:
    """Reconstructs GetAuthKey(ecu_name, index) semantics."""
    return store.auth_blob(ecu_name, index)

__all__ = ["resolve_auth_key"]
