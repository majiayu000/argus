"""Embedded lookup table. Decoding is not execution."""
import base64

_PACKED = "AAECAwQFBgcICQoLDA0ODw=="


def offsets():
    """Return the decoded byte table. Nothing is exec'd, eval'd, or imported."""
    return list(base64.b64decode(_PACKED))
