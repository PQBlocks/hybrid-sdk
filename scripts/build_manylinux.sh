set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# Builds a manylinux_2_28 x86_64 wheel. Run inside quay.io/pypa/manylinux_2_28_x86_64.
dnf -q -y install openssl-devel cmake ninja-build git >/dev/null
git clone -q --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs /tmp/oqs
cmake -S /tmp/oqs -B /tmp/oqs/b -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON -DCMAKE_INSTALL_PREFIX=/opt/oqs >/dev/null
cmake --build /tmp/oqs/b >/dev/null && cmake --install /tmp/oqs/b >/dev/null
cd $ROOT/src/pqblocks_core
cp -L /opt/oqs/lib64/liboqs.so.9 lib/ 2>/dev/null || cp -L /opt/oqs/lib/liboqs.so.9 lib/
I="-I. -I/opt/oqs/include"; L="-Llib -l:liboqs.so.9 -lcrypto -lssl"
gcc -O2 -fPIC -shared $I -o lib/libpqblocks_errors.so pqblocks_errors.c $L -Wl,-rpath,'$ORIGIN'
for m in kem sig policy; do gcc -O2 -fPIC -shared $I -o lib/libpqblocks_$m.so pqblocks_$m.c pqblocks_errors.c $L -Wl,-rpath,'$ORIGIN'; done
gcc -O2 $I -o pqblocks pqblocks_cli.c -Llib -lpqblocks_kem -lpqblocks_sig -lpqblocks_policy -lpqblocks_errors $L -ldl -Wl,-rpath,'$ORIGIN/lib'
cd $ROOT && /opt/python/cp312-cp312/bin/python -m pip -q install build wheel auditwheel >/dev/null
/opt/python/cp312-cp312/bin/python -m build -w -o $ROOT/raw . >/dev/null
/opt/python/cp312-cp312/bin/python -m wheel tags --platform-tag linux_x86_64 --remove $ROOT/raw/*.whl
/opt/python/cp312-cp312/bin/python -m auditwheel repair --plat manylinux_2_28_x86_64 -w $ROOT/dist $ROOT/raw/*linux_x86_64.whl
cd /tmp && /opt/python/cp312-cp312/bin/python -m venv /tmp/t && /tmp/t/bin/pip -q install "$ROOT"/dist/*.whl
for e in "$ROOT"/examples/*.py; do /tmp/t/bin/python "$e" >/dev/null; done && echo "examples OK"
