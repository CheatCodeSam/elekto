# Copyright 2025 The Elekto Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author(s):         Carson Weeks <mail@carsonweeks.com>

import pytest
from elekto.core.encryption import decrypt, encrypt, get_secret_box

def test_same_salt_and_passcode_produce_same_key():
    salt = b"1234567890123456"
    passcode = b'same_passcode'

    box1 = get_secret_box(salt, passcode)
    box2 = get_secret_box(salt, passcode)

    assert box1._key == box2._key

def test_different_salt_produces_different_key():
    passcode = b'same_passcode'
    salt1 = b"one4567890123456"
    salt2 = b"two4567890123456"

    box1 = get_secret_box(salt1, passcode)
    box2 = get_secret_box(salt2, passcode)

    assert box1._key != box2._key

def test_encrypt():
    salt = b"1234567890123456"  
    passcode = "testpass"
    target = "Hello, encryption!"

    ciphertext = encrypt(salt, passcode, target)

    box = get_secret_box(salt , passcode.encode("utf-8"))
    decrypted = box.decrypt(ciphertext)

    assert decrypted == target.encode("utf-8")

def test_decrypt_success():
    salt = b"1234567890123456"
    passcode = "correct-passcode"
    message = "Hello, world!"

    box = get_secret_box(salt, passcode.encode("utf-8"))
    encrypted = box.encrypt(message.encode("utf-8"))

    decrypted_message = decrypt(salt, passcode, encrypted)

    assert decrypted_message == message


def test_decrypt_wrong_passcode():
    salt = b"1234567890123456"
    correct_passcode = "correct-passcode"
    wrong_passcode = "wrong-passcode"
    message = "Secret Message"

    box = get_secret_box(salt, correct_passcode.encode("utf-8"))
    encrypted = box.encrypt(message.encode("utf-8"))

    with pytest.raises(Exception) as exc_info:
        decrypt(salt, wrong_passcode, encrypted)

    assert "Wrong passcode. Decryption Failed!" in str(exc_info.value)
