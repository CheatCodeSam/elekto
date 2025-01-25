# Copyright 2022 The Elekto Authors
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
# Author(s):         Vedant Raghuwanshi <raghuvedant00@gmail.com>


from nacl import secret, pwhash, exceptions


def get_secret_box(salt: bytes, passcode: bytes):
    kdf = pwhash.argon2i.kdf
    key = kdf(secret.SecretBox.KEY_SIZE, passcode, salt)
    box = secret.SecretBox(key)

    return box


def encrypt(salt: bytes, passcode: str, target: str):
    byte_passcode = passcode.encode("utf-8")
    byte_target = target.encode("utf-8")
    box = get_secret_box(salt, byte_passcode)
    encrypted = box.encrypt(byte_target)

    return encrypted


def decrypt(salt: bytes, passcode: str, encrypted: bytes):
    passcode = passcode.encode("utf-8")
    box = get_secret_box(salt, passcode)
    try:
        target = box.decrypt(encrypted).decode("utf-8")

    except exceptions.CryptoError:
        raise Exception("Wrong passcode. Decryption Failed!")

    return target
