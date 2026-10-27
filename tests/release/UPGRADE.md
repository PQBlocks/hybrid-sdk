# Upgrade Guide for pqblocks-core

## Upgrading to v1.0.0

This is the initial release of pqblocks-core, so there are no previous versions to upgrade from.

## Installation

### Prerequisites
- liboqs v0.10.0 or later
- OpenSSL 3.5 or later (with oqs-provider support)
- CMake 3.10 or later
- C compiler supporting C11 standard

### Building from Source

```bash
# Clone the repository
git clone https://github.com/quantum-readiness/pqblocks-core.git
cd pqblocks-core

# Build the libraries and CLI
make

# Run the test suite to verify correctness
make check

# Install system-wide (optional)
sudo make install
```

### Using pqblocks-core in Your Projects

#### C/C++ Projects
Include the header and link against the library:

```c
#include <pqblocks/hybrid.h>
// Link with -lpqblocks
```

#### CLI Tool Usage
The pqblocks CLI provides easy access to all functionality:

```bash
# Generate a new key pair
pqblocks kem keygen --out kem.json

# Encapsulate a shared secret
pqblocks kem encaps --in kem.json --out encaps.json

# Decapsulate to recover the shared secret
pqblocks kem decaps --in encaps.json --out shared.key

# Sign a message
pqblocks sig sign --in sig.json --msg "Hello World" --out signature.bin

# Verify a signature
pqblocks sig verify --in sig.json --msg "Hello World" --sig signature.bin
```

## Backward Compatibility
As this is the initial release (v1.0.0), there are no previous versions to maintain compatibility with. Future releases will follow semantic versioning and maintain backward compatibility within major versions.

## Breaking Changes
No breaking changes in this initial release.

## Deprecations
No deprecations in this initial release.