# QuantumVault-Post-Quantum-Cryptography-PQC-Local-Filesystem

This work is a Python-based local-filesystem vault project intended to use post-quantum key encapsulation as the foundation for file-level encryption. The project currently has the KEM layer implemented and validated against the native liboqs runtime, but the higher-level vault workflow beyond ML-KEM negotiation is not yet a complete production implementation.

## Requirements

- Python 3.14.7 (the installed runtime in this environment is compatible with `liboqs-python==0.16.0.2`)
- Windows 11
- Microsoft Visual Studio 2022 Build Tools with MSVC and the Windows SDK
- CMake and Ninja available in the active shell
- Git

## Dependency installation

```powershell
cd D:\Infotact_Internship\CryptoValut\QuantumVault-Post-Quantum-Cryptography-PQC-Local-Filesystem
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Native liboqs build (Windows)

Use a proper Visual Studio developer shell and build only the ML-KEM algorithms needed for this project:

```powershell
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat'
$cmake = 'C:\Program Files\CMake\bin\cmake.exe'
$ninja = 'C:\Users\Asus\AppData\Local\Python\pythoncore-3.14-64\Scripts\ninja.exe'
$liboqs = 'D:\Infotact_Internship\CryptoValut\QuantumVault-Post-Quantum-Cryptography-PQC-Local-Filesystem\.vendor\liboqs'
cmd /d /c "cd /d `"$liboqs`" && call `"$vs`" -arch=x64 -host_arch=x64 && `"$cmake`" -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD=`"KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024`" -DCMAKE_MAKE_PROGRAM=`"$ninja`" && `"$cmake`" --build build --parallel"
```

Then expose the generated `oqs.dll` to Python:

```powershell
$env:LIBOQS_LIBRARY = 'D:\Infotact_Internship\CryptoValut\QuantumVault-Post-Quantum-Cryptography-PQC-Local-Filesystem\.vendor\liboqs\build\bin'
$env:PATH = "$env:LIBOQS_LIBRARY;$env:PATH"
```

## Verification commands

```powershell
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"
python scripts/check_liboqs_kem.py
pytest -q
python scripts/check_kem_roundtrip.py
```

## Actual project status

The implemented, verified parts are the native liboqs import path and the ML-KEM round-trip logic in `crypto/kem.py`. The repository does not yet contain a complete file-encryption vault workflow, HKDF-based key derivation, or authenticated file storage; those remain explicit gaps rather than assumptions.
