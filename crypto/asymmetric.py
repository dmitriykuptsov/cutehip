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
from Crypto.Hash import SHA256, SHA384, SHA1
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

"""
Base 64 encoding decoding routines
"""
from base64 import b64decode
from base64 import b64encode

class Signature():
	ALG_ID = 0x0;
	def __init__(self, key):
		pass
	def sign(self, data):
		raise Exception("Not implemented");
	def verify(self, sig, data):
		raise Exception("Not implemented");

class ECDSASHA256Signature(Signature):
	ALG_ID = 0x0;
	def __init__(self, key):
		self.key = key;
	def sign(self, data):
		h = SHA256.new(data)
		signer = DSS.new(self.key, 'fips-186-3')
		signature = signer.sign(h);
		return signature
	def verify(self, sig, data):
		h = SHA256.new(data)
		verifier = DSS.new(self.key, 'fips-186-3')
		try:
			verifier.verify(h, bytes(sig))
			return True
		except:
			return False

class ECDSASHA384Signature(Signature):
	ALG_ID = 0x7;
	def __init__(self, key):
		self.key = key;
	def sign(self, data):
		h = SHA384.new(data)
		signer = DSS.new(self.key, 'fips-186-3')
		return signer.sign(h);
	def verify(self, sig, data):
		h = SHA384.new(data)
		verifier = DSS.new(self.key, 'fips-186-3')
		try:
			verifier.verify(h, bytes(sig))
			return True
		except ValueError as e:
			return False

class ECDSASHA1Signature(Signature):
	ALG_ID = 0x9;
	def __init__(self, key):
		self.key = key;
	def sign(self, data):
		h = SHA1.new(data)
		signer = DSS.new(self.key, 'fips-186-3')
		return signer.sign(h);
	def verify(self, sig, data):
		h = SHA1.new(data)
		verifier = DSS.new(self.key, 'fips-186-3')
		try:
			verifier.verify(h, bytes(sig))
			return True
		except ValueError as e:
			return False

class RSASHA256Signature(Signature):
	ALG_ID = 0x5;
	def __init__(self, key):
		self.key = key;
	def sign(self, data):
		h = SHA256.new(data);
		signature = pss.new(self.key).sign(h)
		return signature;
	def verify(self, sig, data):
		h = SHA256.new(data)
		try:
			pss.new(self.key).verify(h, sig)
			return True
		except:
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
		return RSAPublicKey(buffer = buffer);

	@staticmethod
	def load_from_params(e, n):
		"""
		Construct public key from the components
		"""
		return RSAPublicKey(key = RSA.construct((n, e)));

	def __init__(self, buffer = None, key = None):
		"""
		Initializes the buffer
		"""
		if not key:
			self.key = RSA.importKey(buffer)
		else:
			self.key = key;

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
		return RSAPrivateKey(buffer = buffer);

	@staticmethod
	def load_from_params(p, q, d, e, n):
		"""
		Construct private key from the components
		"""
		return RSAPrivateKey(key = RSA.construct((n, e, d, p, q)));

	def __init__(self, buffer = None, key = None):
		if not key:
			self.key = RSA.importKey(buffer)
		else:
			self.key = key;
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

class ECDSAPublicKey():
	
	NIST_P_256 = 0x1;
	NIST_P_384 = 0x2;

	@staticmethod
	def load_pem(filename):
		"""
		Loads the ECDSA private key from PEM file and then parses the key
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
		return ECDSAPublicKey(buffer);

	def __init__(self, buffer = None, key = None):
		if buffer:
			self.key = ECC.import_key(buffer);
			if self.key.curve == 'NIST P-256':
				self.curve_id = ECDSAPublicKey.NIST_P_256;
			elif self.key.curve == 'NIST P-384':
				self.curve_id = ECDSAPublicKey.NIST_P_384;
			else:
				raise Exception("Unsupported curve");
		elif key:
			self.key = key;
			if self.key.curve == 'NIST P-256':
				self.curve_id = ECDSAPublicKey.NIST_P_256;
			elif self.key.curve == 'NIST P-384':
				self.curve_id = ECDSAPublicKey.NIST_P_384;
			else:
				raise Exception("Unsupported curve");

	@staticmethod
	def load_buffer(buffer):
		return ECDSAPublicKey(buffer = buffer);

	@staticmethod
	def load_from_params(curve = None, x = None, y = None):
		"""
		Construct public key from the components
		"""
		if curve == ECDSAPublicKey.NIST_P_256:
			return ECDSAPublicKey(key = ECC.construct(curve = 'NIST P-256', point_x = x, point_y = y));
		elif curve == ECDSAPublicKey.NIST_P_384:
			return ECDSAPublicKey(key = ECC.construct(curve = 'NIST P-384', point_x = x, point_y = y));
		else:
			raise Exception("Unsupported curve");


	def get_curve_id(self):
		return self.curve_id;

	def get_key_info(self):
		return self.key

	def get_x(self):
		return int(self.key.pointQ.x);

	def get_y(self):
		return int(self.key.pointQ.y);

	

class ECDSAPrivateKey():
	NIST_P_256 = 0x1;
	NIST_P_384 = 0x2;

	@staticmethod
	def load_pem(filename):
		"""
		Loads the ECDSA private key from PEM file and then parses the key
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
		return ECDSAPrivateKey(buffer);

	@staticmethod
	def load_buffer(buffer):
		return ECDSAPrivateKey(buffer);

	@staticmethod
	def load_from_params(curve = None, d = None, x = None, y = None):
		"""
		Construct public key from the components
		"""
		return ECDSAPrivateKey(key = ECC.construct(curve = curve, d = d, point_x = x, point_y = y));

	def __init__(self, buffer = None, key = None):
		if buffer:
			self.key = ECC.import_key(buffer);
			if self.key.curve == 'NIST P-256':
				self.curve_id = ECDSAPrivateKey.NIST_P_256;
			elif self.key.curve == 'NIST P-384':
				self.curve_id = ECDSAPrivateKey.NIST_P_384;
			else:
				raise Exception("Unsupported curve");
		elif key:
			self.key = key;
			if self.key.curve == 'NIST P-256':
				self.curve_id = ECDSAPrivateKey.NIST_P_256;
			elif self.key.curve == 'NIST P-384':
				self.curve_id = ECDSAPrivateKey.NIST_P_384;
			else:
				raise Exception("Unsupported curve");

	def get_key_info(self):
		return self.key

	def get_d(self):
		return int(self.key.d);

	def get_x(self):
		return int(self.key.pointQ.x);

	def get_y(self):
		return int(self.key.pointQ.y);

class ECDSALowPublicKey():
	
	SECP160R1 = 0x1;

	@staticmethod
	def load_pem(filename):
		"""
		Loads the ECDSA private key from PEM file and then parses the key
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
		return ECDSALowPublicKey(buffer);

	def __init__(self, buffer = None):
		
			raise Exception("Unsupported curve");

	def __init__(self, buffer = None, key = None):
		if buffer:
			self.key = ECC.import_key(buffer);
			if self.key.curve == 'SECP160R1':
				self.curve_id = ECDSALowPublicKey.SECP160R1;
			else:
				raise Exception("Unsupported curve");
		elif key:
			self.key = key;
			if self.key.curve == 'SECP160R1':
				self.curve_id = ECDSALowPublicKey.SECP160R1;
			else:
				raise Exception("Unsupported curve");

	@staticmethod
	def load_buffer(buffer):
		return ECDSALowPublicKey(buffer = buffer);

	@staticmethod
	def load_from_params(curve = None, x = None, y = None):
		"""
		Construct public key from the components
		"""
		if curve == ECDSALowPublicKey.SECP160R1:
			return ECDSAPublicKey(key = ECC.construct(curve = 'SECP160R1', point_x = x, point_y = y));
		else:
			raise Exception("Unsupported curve");

	def get_curve_id(self):
		return self.curve_id;

	def get_key_info(self):
		return self.key

	def get_x(self):
		return int(self.key.pointQ.x);

	def get_y(self):
		return int(self.key.pointQ.y);

	

class ECDSALowPrivateKey():
	SECP160R1 = 0x1;

	@staticmethod
	def load_pem(filename):
		"""
		Loads the ECDSA private key from PEM file and then parses the key
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
		return ECDSALowPrivateKey(buffer);

	@staticmethod
	def load_from_params(curve = None, d = None, x = None, y = None):
		"""
		Construct public key from the components
		"""
		return ECDSALowPrivateKey(key = ECC.construct(curve = curve, d = d, point_x = x, point_y = y));

	def __init__(self, buffer = None, key = None):
		if buffer:
			self.key = ECC.import_key(buffer);
			if self.key.curve == 'SECP160R1':
				self.curve_id = ECDSALowPrivateKey.SECP160R1;
			else:
				raise Exception("Unsupported curve");
		elif key:
			self.key = key;
			if self.key.curve == 'SECP160R1':
				self.curve_id = ECDSALowPrivateKey.SECP160R1;
			else:
				raise Exception("Unsupported curve");
	@staticmethod
	def load_buffer(buffer):
		return ECDSALowPrivateKey(buffer);

	def get_key_info(self):
		return self.key

	def get_d(self):
		return int(self.key.d);

	def get_x(self):
		return int(self.key.pointQ.x);

	def get_y(self):
		return int(self.key.pointQ.y);

