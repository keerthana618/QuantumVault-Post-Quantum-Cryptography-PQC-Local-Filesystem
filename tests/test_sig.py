
import pytest
 
from crypto.errors import InvalidKeyError, SigningError, UnsupportedAlgorithmError
from crypto.sig import ALL_VARIANTS, DEFAULT_VARIANT, MLDSA, get_signer
 
MESSAGE = b"vault header bytes"
 
 
@pytest.fixture(params=ALL_VARIANTS)
def signer(request):
    try:
        return MLDSA(request.param)
    except UnsupportedAlgorithmError:
        pytest.skip(f"{request.param} not enabled in this liboqs build")
 
 
@pytest.fixture
def keys(signer):
    return signer.generate_keypair()
 
 
def flip_first_byte(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]
 
 
def test_sign_and_verify(signer, keys):
    public_key, secret_key = keys
    signature = signer.sign(secret_key, MESSAGE)
    assert signer.verify(public_key, MESSAGE, signature) is True
 
 
def test_output_sizes_match_liboqs(signer, keys):
    public_key, secret_key = keys
    signature = signer.sign(secret_key, MESSAGE)
    assert len(public_key) == signer.sizes.public_key
    assert len(secret_key) == signer.sizes.secret_key
    assert len(signature) == signer.sizes.signature
 
 
def test_empty_message_can_be_signed(signer, keys):
    public_key, secret_key = keys
    signature = signer.sign(secret_key, b"")
    assert signer.verify(public_key, b"", signature) is True
 
 
def test_tampered_message_rejected(signer, keys):
    public_key, secret_key = keys
    signature = signer.sign(secret_key, MESSAGE)
    assert signer.verify(public_key, flip_first_byte(MESSAGE), signature) is False
 
 
def test_tampered_signature_rejected(signer, keys):
    public_key, secret_key = keys
    signature = signer.sign(secret_key, MESSAGE)
    assert signer.verify(public_key, MESSAGE, flip_first_byte(signature)) is False
 
 
def test_wrong_public_key_rejected(signer, keys):
    _, secret_key = keys
    other_public_key, _ = signer.generate_keypair()
    signature = signer.sign(secret_key, MESSAGE)
    assert signer.verify(other_public_key, MESSAGE, signature) is False
 
 
def test_wrong_length_signature_returns_false(signer, keys):
    public_key, secret_key = keys
    signature = signer.sign(secret_key, MESSAGE)
    assert signer.verify(public_key, MESSAGE, signature[:-1]) is False
    assert signer.verify(public_key, MESSAGE, b"") is False
 
 
def test_wrong_length_keys_rejected(signer, keys):
    public_key, secret_key = keys
    signature = signer.sign(secret_key, MESSAGE)
    with pytest.raises(InvalidKeyError):
        signer.sign(secret_key[:-1], MESSAGE)
    with pytest.raises(InvalidKeyError):
        signer.verify(public_key[:-1], MESSAGE, signature)
 
 
def test_non_bytes_inputs_rejected(signer, keys):
    public_key, secret_key = keys
    with pytest.raises(SigningError):
        signer.sign(secret_key, "not bytes")
    with pytest.raises(InvalidKeyError):
        signer.sign("not bytes", MESSAGE)
    with pytest.raises(SigningError):
        signer.verify(public_key, MESSAGE, "not bytes")
 
 
def test_context_separates_signatures(signer, keys):
    if not signer.supports_context:
        pytest.skip("this liboqs-python version has no context string support")
    public_key, secret_key = keys
    signature = signer.sign(secret_key, MESSAGE, context=b"purpose-a")
    assert signer.verify(public_key, MESSAGE, signature, context=b"purpose-a") is True
    assert signer.verify(public_key, MESSAGE, signature, context=b"purpose-b") is False
    assert signer.verify(public_key, MESSAGE, signature) is False
 
 
def test_context_too_long_rejected(signer, keys):
    if not signer.supports_context:
        pytest.skip("this liboqs-python version has no context string support")
    _, secret_key = keys
    with pytest.raises(SigningError):
        signer.sign(secret_key, MESSAGE, context=b"x" * 256)
 
 
def test_unknown_variant_rejected():
    with pytest.raises(UnsupportedAlgorithmError):
        MLDSA("ML-DSA-999")
 
 
def test_factory_default_variant():
    try:
        assert get_signer().variant == DEFAULT_VARIANT
    except UnsupportedAlgorithmError:
        pytest.skip("default variant not enabled in this liboqs build")
 