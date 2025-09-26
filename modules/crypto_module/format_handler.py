# modules/crypto/format_handler.py
import json, base64

def package_encrypted(metadata: dict, data_bytes: bytes, key_bytes: bytes) -> bytes:
    """Gộp thành JSON: {'meta':..., 'key':..., 'data':...}"""
    payload = {
      'meta': metadata,
      'key': base64.b64encode(key_bytes).decode(),
      'data': base64.b64encode(data_bytes).decode()
    }
    return json.dumps(payload).encode()

def unpack_encrypted(pkg_bytes: bytes):
    obj = json.loads(pkg_bytes.decode())
    import base64
    return (
      obj['meta'],
      base64.b64decode(obj['key']),
      base64.b64decode(obj['data'])
    )