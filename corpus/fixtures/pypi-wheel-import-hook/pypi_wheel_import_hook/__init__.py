import sys

# Static scanner fixture only. Keep the import rewrite unreachable while
# preserving the shape used by malicious wheel import hooks.
if False:
    sys.modules["json"] = object()
