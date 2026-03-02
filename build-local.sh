#!/bin/bash
# Build Ghostty.app for macOS with symbols and archive dSYM for crash triage
#
# Usage: ./build-local.sh [--debug] [--clean] [--run]
#
# This script:
# 1. Builds Ghostty.app in ReleaseLocal or Debug configuration
# 2. Extracts the debug UUIDs from the dSYM
# 3. Archives the dSYM to ~/.ghostty-dsyms/<UUID>/ for crash symbolication
#
# Modes:
#   Default (release): ReleaseLocal config, bundle ID com.mitchellh.ghostty
#   --debug:           Debug config, bundle ID com.mitchellh.ghostty.debug
#                      Safe to run alongside a production Ghostty install.

set -euo pipefail

# Defaults
MODE="release"
CLEAN=false
RUN=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --debug)
            MODE="debug"
            ;;
        --clean)
            CLEAN=true
            ;;
        --run)
            RUN=true
            ;;
        --help|-h)
            echo "Usage: $0 [--debug] [--clean] [--run]"
            echo ""
            echo "Options:"
            echo "  --debug    Build Debug config (separate bundle ID, safe alongside production)"
            echo "  --clean    Clean build directory before building"
            echo "  --run      Open the built app after a successful build"
            exit 0
            ;;
    esac
done

# Configure paths and flags based on mode
DSYM_ARCHIVE="${HOME}/.ghostty-dsyms"

if [ "$MODE" = "debug" ]; then
    BUILD_DIR="zig-out"
    ZIG_BUILD_ARGS="-Dxcframework-target=native"
    CONFIG_LABEL="Debug (com.mitchellh.ghostty.debug)"
else
    BUILD_DIR="macos/build/ReleaseLocal"
    ZIG_BUILD_ARGS="--release=fast -Dxcframework-target=native"
    CONFIG_LABEL="ReleaseLocal (com.mitchellh.ghostty)"
fi

APP_PATH="${BUILD_DIR}/Ghostty.app"
DSYM_PATH="${APP_PATH}.dSYM"

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning ${BUILD_DIR}..."
    rm -rf "${BUILD_DIR}"
fi

# Build
echo "Building Ghostty.app [${CONFIG_LABEL}]..."
# shellcheck disable=SC2086
zig build ${ZIG_BUILD_ARGS}

# Verify build produced an app
if [ ! -d "${APP_PATH}" ]; then
    echo "Error: App not found at ${APP_PATH}"
    exit 1
fi

# Archive dSYM (release builds only — debug builds don't produce one)
if [ -d "${DSYM_PATH}" ]; then
    mkdir -p "${DSYM_ARCHIVE}"

    echo "Archiving dSYM..."
    dwarfdump --uuid "${DSYM_PATH}" | while read -r line; do
        # Parse: UUID: <uuid> (<arch>) <path>
        UUID=$(echo "$line" | awk '{print $2}')
        ARCH=$(echo "$line" | grep -oE '\(([^)]+)\)' | tr -d '()')

        if [ -n "${UUID}" ]; then
            TARGET_DIR="${DSYM_ARCHIVE}/${UUID}"

            if [ -d "${TARGET_DIR}" ]; then
                echo "  Replacing existing dSYM for ${UUID} (${ARCH})"
                rm -rf "${TARGET_DIR}"
            fi

            mkdir -p "${TARGET_DIR}"
            cp -R "${DSYM_PATH}" "${TARGET_DIR}/"
            echo "  Archived: ${UUID} (${ARCH})"
        fi
    done
fi

# Summary
echo ""
echo "Build complete!"
echo "  Config:  ${CONFIG_LABEL}"
echo "  App:     ${APP_PATH}"
if [ -d "${DSYM_PATH}" ]; then
    echo "  dSYM:    ${DSYM_PATH}"
    echo "  Archive: ${DSYM_ARCHIVE}/"
fi

if [ "$MODE" = "debug" ]; then
    echo ""
    echo "Debug build uses a separate bundle ID — safe to run alongside production Ghostty."
fi

echo ""
echo "To run: open ${APP_PATH}"

# Open if requested
if [ "$RUN" = true ]; then
    echo ""
    echo "Opening ${APP_PATH}..."
    open "${APP_PATH}"
fi
