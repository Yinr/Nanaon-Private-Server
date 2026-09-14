"""Resolve build toolchain locations without hard-coding machine paths.

Resolution order for every tool:

1. explicit value (CLI argument or ``.env``, already resolved by callers);
2. standard Android SDK layout under ``NANAON_SDK_ROOT``, ``ANDROID_HOME``
   or ``ANDROID_SDK_ROOT`` (build-tools 37.0.0 preferred, else the newest
   installed; platforms/android-34 preferred, else the newest android.jar);
3. for apktool: an ``apktool`` executable on ``PATH`` — either a standalone
   JAR or the conventional wrapper layout with ``apktool.jar`` beside it;
4. otherwise raise with guidance on which variable to set.
"""

import os
import shutil
from pathlib import Path

BUILD_TOOLS_VERSION = "37.0.0"
ANDROID_PLATFORM = "android-34"
SDK_ENV_VARS = ("NANAON_SDK_ROOT", "ANDROID_HOME", "ANDROID_SDK_ROOT")


def _sdk_root() -> Path | None:
    for name in SDK_ENV_VARS:
        value = os.environ.get(name)
        if value and Path(value).is_dir():
            return Path(value)
    return None


def _newest_child(directory: Path) -> Path | None:
    if not directory.is_dir():
        return None
    children = sorted(child for child in directory.iterdir() if child.is_dir())
    return children[-1] if children else None


def resolve_build_tools(explicit: Path | str | None = None) -> Path:
    if explicit:
        path = Path(explicit)
        if not path.is_dir():
            raise RuntimeError(f"build-tools directory not found: {path}")
        return path
    root = _sdk_root()
    if root:
        pinned = root / "build-tools" / BUILD_TOOLS_VERSION
        if pinned.is_dir():
            return pinned
        newest = _newest_child(root / "build-tools")
        if newest:
            return newest
    raise RuntimeError(
        "Android build-tools not found. Set NANAON_BUILD_TOOLS, or point "
        "NANAON_SDK_ROOT / ANDROID_HOME / ANDROID_SDK_ROOT at an SDK "
        f"containing build-tools/{BUILD_TOOLS_VERSION}."
    )


def resolve_android_jar(explicit: Path | str | None = None) -> Path:
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise RuntimeError(f"android.jar not found: {path}")
        return path
    root = _sdk_root()
    if root:
        pinned = root / "platforms" / ANDROID_PLATFORM / "android.jar"
        if pinned.is_file():
            return pinned
        platforms = _newest_child(root / "platforms")
        if platforms:
            jar = platforms / "android.jar"
            if jar.is_file():
                return jar
    raise RuntimeError(
        "android.jar not found. Set NANAON_ANDROID_JAR, or point "
        "NANAON_SDK_ROOT / ANDROID_HOME / ANDROID_SDK_ROOT at an SDK "
        f"containing platforms/{ANDROID_PLATFORM}."
    )


def resolve_apktool_jar(explicit: Path | str | None = None) -> Path:
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise RuntimeError(f"apktool JAR not found: {path}")
        return path
    found = shutil.which("apktool")
    if found:
        path = Path(found)
        if path.suffix.lower() == ".jar" and path.is_file():
            return path
        sibling = path.with_name("apktool.jar")
        if sibling.is_file():
            return sibling
    raise RuntimeError(
        "apktool JAR not found. Set NANAON_APKTOOL_JAR, or install apktool "
        "on PATH (a standalone JAR, or the conventional wrapper layout with "
        "apktool.jar beside the launcher)."
    )
