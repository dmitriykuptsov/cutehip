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

from Crypto.Cipher import AES

class SymmetricCrypto():
	# PKCS7 padding is described in
	# https://tools.ietf.org/html/rfc5652
	def pad(self, plaintext, block_size):
		return plaintext + bytearray((block_size - len(plaintext) % block_size) * \
			chr(block_size - len(plaintext) % block_size), encoding="ascii")

	def unpad(self, ciphertext):
		return ciphertext[:-ord(ciphertext[len(ciphertext) - 1])];	
		
	def encrypt(self, key, iv, data):
		pass
	def decrypt(self, key, iv, data):
		pass


class AESCipher(SymmetricCrypto):

	KEY_SIZE_128_BITS = 0x16;
	MODE_CBC = AES.MODE_CBC;
	BLOCK_SIZE = AES.block_size;

	"""
	Advanced Encryption Standard
	"""
	def __init__(self):
		pass

	def encrypt(self, key, iv, data):
		"""
		Encryptes the plaintext using
		"""
		cipher = AES.new(key, self.mode, iv);
		return cipher.encrypt(self.pad(data, block_size));

	def decrypt(self, key, iv, data):
		"""
		This method decryptes the ciphertext
		"""
		cipher = AES.new(key, self.mode, iv);
		return self.unpad(cipher.decrypt(data));

class AES128CBCCipher(SymmetricCrypto):

	KEY_SIZE_128_BITS = 0x16;
	MODE_CBC = AES.MODE_CBC;
	BLOCK_SIZE = AES.block_size;

	"""
	Advanced Encryption Standard
	"""
	def __init__(self):
		pass

	def encrypt(self, key, iv, data):
		"""
		Encryptes the plaintext using
		"""
		cipher = AES.new(key, self.mode, iv);
		return cipher.encrypt(self.pad(data, block_size));

	def decrypt(self, key, iv, data):
		"""
		This method decryptes the ciphertext
		"""
		cipher = AES.new(key, self.mode, iv);
		return self.unpad(cipher.decrypt(data));
