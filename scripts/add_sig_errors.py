import shutil

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import crypto.errors as errors

NEW = {
    "SigningError": "Signing failed , or its inputs are invalid.",
    "SignatureBackendError": "The signature library (liboqs) is not availabe",
    }
missing = [name for name in NEW if not hasattr(errors, name)]
if not missing:
    print("Nothing to add: both error classed already exits")
    sys.exit(0)

invalid_key = getattr(errors, "InvalidKey", None)
base = invalid_key.__bases__[0] if invalid_key else "Exception"

path = Path(errors.__file__)
shutil.copy(path, str(path) + ".bak")
text = path.read_text()
if not text.endswith("\n"):
    text += "\n"
for name in missing:
    text += f'\n\nclass {name}({base}):\n    """{NEW[name]}"""\n'
path.write_text(text)
print(f"Added to {path}: {', '.join(missing)} (base class: {base})")
print(f"Backup saved as {path}.bak")