import os
import stat

import pytest

from crypto import keystore
from crypto.errors import KeystoreError, WrongPasswordError

FAST = {"time_cost": 1, "memory_cost": 1024, "parallelism": 1}  # fast for tests
SECRET = os.urandom(64)


def test_round_trip(tmp_path):
    p = str(tmp_path / "k.key")
    keystore.save_private_key(p, SECRET, "correct horse", FAST)
    assert keystore.load_private_key(p, "correct horse") == SECRET


def test_wrong_password_fails(tmp_path):
    p = str(tmp_path / "k.key")
    keystore.save_private_key(p, SECRET, "correct horse", FAST)
    with pytest.raises(WrongPasswordError):
        keystore.load_private_key(p, "wrong")


def test_file_mode_is_600(tmp_path):
    p = str(tmp_path / "k.key")
    keystore.save_private_key(p, SECRET, "pw", FAST)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_tampered_params_fail(tmp_path):
    import json
    p = str(tmp_path / "k.key")
    keystore.save_private_key(p, SECRET, "pw", FAST)
    doc = json.load(open(p))
    doc["params"]["time_cost"] = 2
    json.dump(doc, open(p, "w"))
    with pytest.raises(WrongPasswordError):
        keystore.load_private_key(p, "pw")


def test_missing_file(tmp_path):
    with pytest.raises(KeystoreError):
        keystore.load_private_key(str(tmp_path / "nope.key"), "pw")


def test_same_password_gives_different_files(tmp_path):
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    keystore.save_private_key(a, SECRET, "pw", FAST)
    keystore.save_private_key(b, SECRET, "pw", FAST)
    assert open(a).read() != open(b).read()