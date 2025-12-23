#!/bin/bash
# Build Ghostty.app for macOS with symbols and archive dSYM for crash triage
#
# Usage: ./build-local-release.sh [--clean]
#
# This script:
# 1. Builds Ghostty.app in ReleaseLocal configuration with debug symbols
# 2. Extracts the debug UUIDs from the dSYM
# 3. Archives the dSYM to ~/.ghostty-dsyms/<UUID>/ for crash symbolication

set -euo pipefail

DSYM_ARCHIVE="${HOME}/.ghostty-dsyms"
BUILD_DIR="macos/build/ReleaseLocal"
DSYM_PATH="${BUILD_DIR}/Ghostty.app.dSYM"

# Parse arguments
CLEAN=false
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--clean]"
            echo ""
            echo "Options:"
            echo "  --clean    Clean build directory before building"
            exit 0
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo "Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
fi

# Build with release mode (uses ReleaseLocal xcode configuration)
echo "Building Ghostty.app with symbols..."
zig build --release=fast

# Verify build succeeded
if [ ! -d "${DSYM_PATH}" ]; then
    echo "Error: dSYM not found at ${DSYM_PATH}"
    exit 1
fi

# Create archive directory
mkdir -p "${DSYM_ARCHIVE}"

# Extract UUIDs and archive
echo "Archiving dSYM..."
dwarfdump --uuid "${DSYM_PATH}" | while read -r line; do
    # Parse: UUID: <uuid> (<arch>) <path>
    UUID=$(echo "$line" | awk '{print $2}')
    ARCH=$(echo "$line" | grep -oE '\(([^)]+)\)' | tr -d '()')

    if [ -n "${UUID}" ]; then
        TARGET_DIR="${DSYM_ARCHIVE}/${UUID}"

        # Remove existing archive for this UUID
        if [ -d "${TARGET_DIR}" ]; then
            echo "  Replacing existing dSYM for ${UUID} (${ARCH})"
            rm -rf "${TARGET_DIR}"
        fi

        mkdir -p "${TARGET_DIR}"
        cp -R "${DSYM_PATH}" "${TARGET_DIR}/"
        echo "  Archived: ${UUID} (${ARCH})"
    fi
done

# Print summary
echo ""
echo "Build complete!"
echo "  App: ${BUILD_DIR}/Ghostty.app"
echo "  dSYM: ${DSYM_PATH}"
echo "  Archive: ${DSYM_ARCHIVE}/"
echo ""
echo "To run: open ${BUILD_DIR}/Ghostty.app"
echo "Or use: zig build run --release=fast"
