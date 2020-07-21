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
	BLOCK_SIZE = 0x0;
	KEY_SIZE_BITS = 0x0;
	# PKCS7 padding is described in
	# https://tools.ietf.org/html/rfc5652
	def pad(self, plaintext, block_size):
		#return plaintext + bytearray((block_size - len(plaintext) % block_size) * \
		#	chr(block_size - len(plaintext) % block_size), encoding="ascii")
		return plaintext;

	def unpad(self, ciphertext):
		#return ciphertext[:-ord(ciphertext[len(ciphertext) - 1])];	
		return ciphertext;
		
	def encrypt(self, key, iv, data):
		pass
	def decrypt(self, key, iv, data):
		pass

class NullCipher(SymmetricCrypto):
	BLOCK_SIZE = 0x10;
	KEY_SIZE_BITS = 0x0;
	ALG_ID = 0x1;
	def encrypt(self, key = None, iv = None, data = None):
		return data;
	def decrypt(self, key = None, iv = None, data = None):
		return data;

class AESCipher(SymmetricCrypto):

	KEY_SIZE_BITS = 0x10;
	MODE_CBC = AES.MODE_CBC;
	BLOCK_SIZE = AES.block_size;
	ALG_ID = 0x2;

	"""
	Advanced Encryption Standard
	"""
	def __init__(self):
		pass

	def encrypt(self, key, iv, data):
		"""
		Encryptes the plaintext using
		"""
		cipher = AES.new(key, AESCipher.MODE_CBC, iv);
		return cipher.encrypt(self.pad(data, AESCipher.BLOCK_SIZE));

	def decrypt(self, key, iv, data):
		"""
		This method decryptes the ciphertext
		"""
		cipher = AES.new(key, AESCipher.MODE_CBC, iv);
		return self.unpad(cipher.decrypt(data));

class AES128CBCCipher(SymmetricCrypto):

	KEY_SIZE_BITS = 0x10;
	MODE_CBC = AES.MODE_CBC;
	BLOCK_SIZE = AES.block_size;
	ALG_ID = 0x2;
	
	"""
	Advanced Encryption Standard
	"""
	def __init__(self):
		pass

	def encrypt(self, key, iv, data):
		"""
		Encryptes the plaintext using
		"""
		cipher = AES.new(key, AES128CBCCipher.MODE_CBC, iv);
		return cipher.encrypt(self.pad(data, AES128CBCCipher.BLOCK_SIZE));

	def decrypt(self, key, iv, data):
		"""
		This method decryptes the ciphertext
		"""
		cipher = AES.new(key, AES128CBCCipher.MODE_CBC, iv);
		return self.unpad(cipher.decrypt(data));

class AES256CBCCipher(SymmetricCrypto):

	KEY_SIZE_BITS = 0x20;
	MODE_CBC = AES.MODE_CBC;
	BLOCK_SIZE = AES.block_size;
	ALG_ID = 0x4;
	
	"""
	Advanced Encryption Standard
	"""
	def __init__(self):
		pass

	def encrypt(self, key, iv, data):
		"""
		Encryptes the plaintext using
		"""
		cipher = AES.new(key, AES256CBCCipher.MODE_CBC, iv);
		return cipher.encrypt(self.pad(data, AES256CBCCipher.BLOCK_SIZE));

	def decrypt(self, key, iv, data):
		"""
		This method decryptes the ciphertext
		"""
		cipher = AES.new(key, AES256CBCCipher.MODE_CBC, iv);
		return self.unpad(cipher.decrypt(data));
