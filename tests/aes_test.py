#!/usr/bin/python3

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from os import urandom
from symmetric import *
key = urandom(AESCipher.KEY_SIZE_128_BITS);
iv = urandom(AESCipher.BLOCK_SIZE);
data = bytearray("Hello world!".encode("ascii"));
cipher = AESCipher(AESCipher.MODE_CBC, key, iv);
ciphertext = cipher.encrypt(data);
assert cipher.decrypt(ciphertext) == b"Hello world!";