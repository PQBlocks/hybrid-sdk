import os
import sys

# Configure library paths for tests
_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)
_src = os.path.join(_root, "src")
_local_lib = os.path.expanduser("~/.local/lib")

_candidates = [_src, os.path.join(_src, "pqblocks_core", "lib"), _local_lib]
try:
    import pqblocks_core
    _pkg_lib = os.path.join(os.path.dirname(pqblocks_core.__file__), "lib")
    if os.path.isdir(_pkg_lib):
        _candidates.insert(0, _pkg_lib)
except ImportError:
    pass

_existing = os.environ.get("LD_LIBRARY_PATH", "")
_new_paths = [p for p in _candidates if os.path.isdir(p)]
os.environ["LD_LIBRARY_PATH"] = ":".join(_new_paths + ([_existing] if _existing else []))

# Ensure src/ has symlinks to library .so files if src/ exists
if os.path.isdir(_src):
    _lib_dir = os.path.join(_src, "pqblocks_core", "lib")
    if os.path.isdir(_lib_dir):
        for fname in os.listdir(_lib_dir):
            if fname.endswith(".so") or ".so." in fname:
                target = os.path.join(_src, fname)
                source = os.path.join(_lib_dir, fname)
                if not os.path.exists(target):
                    try:
                        os.symlink(source, target)
                    except OSError:
                        pass
