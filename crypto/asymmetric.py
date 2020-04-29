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

"""
Cryptographic modules
"""
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA


"""
Base 64 encoding decoding routines
"""
from base64 import b64decode
from base64 import b64encode

class Signature():
	def __init__(self, key):
		pass
	def sign(self, data):
		raise Exception("Not implemented");
	def verify(self, sig, data):
		raise Exception("Not implemented");

class ECDSASHA256Signature(Signature):
	def __init__(self, key):
		self.key = key;
	def sign(self, data):
		h = SHA256.new(data)
		signer = DSS.new(self.key, 'fips-186-3')
		signature = signer.sign(h)
	def verify(self, sig, data):
		h = SHA256.new(data)
		verifier = DSS.new(self.key, 'fips-186-3')
		try:
			verifier.verify(h, sig)
			return True
		except ValueError:
			return False

class RSASHA256Signature(Signature):
	def __init__(self, key):
		self.key = key;
	def sign(self, data):
		h = SHA256.new(data);
		signature = pkcs1_15.new(self.key).sign(h);
	def verify(self, sig, data):
		h = SHA256.new(data)
		try:
			pkcs1_15.new(self.key).verify(h, sig)
			return True
		except ValueError:
			return False

# https://tools.ietf.org/html/rfc3447#appendix-A
class RSAPublicKey():
	@staticmethod
	def load_pem(filename):
		"""
		Loads the RSA private key from PEM file and then parses the key
		"""
		buffer = [];
		b64_contents = "";
		try:
			handle = open(filename, "r");
			raw_contents = handle.readlines();
			for line in raw_contents:
				if line.startswith("----"):
					continue
				b64_contents += line.strip();
		except Exception as e:
			raise Exception("Failed to read PEM file: " + str(e));
		buffer = b64decode(b64_contents);
		return RSAPublicKey(buffer);

	@staticmethod
	def load_buffer(buffer):
		return RSAPublicKey(buffer);

	@staticmethod
	def load_from_params(e, n):
		pass

	def __init__(self, buffer):
		"""
		Initializes the buffer
		"""
		self.key = RSA.importKey(buffer)
	def get_key_info(self):
		"""
		Returns the RSA public key
		"""
		return self.key;
	def get_modulus(self):
		"""
		Gets the modulus 
		"""
		return self.key.n;
	def get_public_exponent(self):
		"""
		Gets the public exponent of the key
		"""
		return self.key.e;

class RSAPrivateKey():
	@staticmethod
	def load_pem(filename):
		"""
		Loads the RSA private key from PEM file and then parses the key
		"""
		buffer = [];
		b64_contents = "";
		try:
			handle = open(filename, "r");
			raw_contents = handle.readlines();
			for line in raw_contents:
				if line.startswith("----"):
					continue
				b64_contents += line.strip();
		except Exception as e:
			raise Exception("Failed to read PEM file: " + str(e));
		buffer = b64decode(b64_contents);
		return RSAPrivateKey(buffer);

	@staticmethod
	def load_buffer(buffer):
		return RSAPrivateKey(buffer);

	@staticmethod
	def load_from_params(p, q, e, m):
		pass

	def __init__(self, buffer):
		self.key=RSA.importKey(buffer)
	def get_key_info(self):
		"""
		Returns the RSA private key
		"""
		return self.key;
	def get_modulus(self):
		"""
		Gets the modulus 
		"""
		return self.key.n;
	def get_p_prime(self):
		"""
		Gets the first prime of the key.
		"""
		return self.key.p;
	def get_q_prime(self):
		"""
		Gets the second prime of the key
		"""
		return self.key.q;
	def get_private_exponent(self):
		"""
		Gets the private exponent
		"""
		return self.key.d;
