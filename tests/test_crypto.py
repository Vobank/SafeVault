# -*- coding: utf-8 -*-
"""Тесты крипто-ядра Сейфа: encrypt_bytes / decrypt_bytes."""
import struct

import pytest
from cryptography.exceptions import InvalidTag

import sejf

REAL_SCRYPT_N = sejf.SCRYPT_N   # запоминаем до того, как фикстура его уменьшит


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    """Настоящий scrypt (N=2^17) медленный — в тестах берём лёгкий N."""
    monkeypatch.setattr(sejf, "SCRYPT_N", 2 ** 10)


def test_roundtrip_returns_name_and_data():
    blob = sejf.encrypt_bytes("pass123", b"secret data", name=b"report.pdf")
    assert sejf.decrypt_bytes("pass123", blob) == (b"report.pdf", b"secret data")


@pytest.mark.parametrize("password, data", [
    ("пароль-кириллицей", "заметка: код 4711".encode("utf-8")),
    ("p", b""),                       # пустые данные
    ("x" * 200, bytes(range(256)) * 1000),  # длинный пароль и ~256 КБ бинарных данных
])
def test_roundtrip_various_inputs(password, data):
    blob = sejf.encrypt_bytes(password, data)
    assert sejf.decrypt_bytes(password, blob) == (b"", data)


def test_wrong_password_is_rejected():
    blob = sejf.encrypt_bytes("right", b"data")
    with pytest.raises(InvalidTag):
        sejf.decrypt_bytes("wrong", blob)


@pytest.mark.parametrize("pos", [6, 6 + sejf.SALT_LEN, -1])   # соль, nonce, тег
def test_tampered_blob_is_rejected(pos):
    blob = bytearray(sejf.encrypt_bytes("pw", b"important"))
    blob[pos] ^= 0x01
    with pytest.raises(InvalidTag):
        sejf.decrypt_bytes("pw", bytes(blob))


def test_foreign_file_raises_value_error():
    with pytest.raises(ValueError):
        sejf.decrypt_bytes("pw", b"PK\x03\x04 not a sejf file")


def test_same_input_gives_different_ciphertexts():
    a = sejf.encrypt_bytes("pw", b"data")
    b = sejf.encrypt_bytes("pw", b"data")
    assert a != b                                   # случайные соль и nonce
    assert sejf.decrypt_bytes("pw", a) == sejf.decrypt_bytes("pw", b)


def test_blob_layout():
    name, data = b"a.txt", b"hello"
    blob = sejf.encrypt_bytes("pw", data, name=name)
    assert blob.startswith(sejf.MAGIC)
    tag_len = 16
    payload_len = len(struct.pack(">H", 0)) + len(name) + len(data)
    assert len(blob) == len(sejf.MAGIC) + sejf.SALT_LEN + sejf.NONCE_LEN + payload_len + tag_len
    assert name not in blob and data not in blob   # имя файла тоже зашифровано


def test_production_kdf_params_are_strong():
    assert REAL_SCRYPT_N >= 2 ** 17
    assert sejf.KEY_LEN == 32
