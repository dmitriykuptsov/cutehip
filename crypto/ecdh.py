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

#https://ru.qwe.wiki/wiki/Elliptic_curve

import sys
import os
sys.path.append(os.getcwd())

import utils
#from utils.misc import misc.Math, misc.ECPoint
from utils import misc
from binascii import unhexlify
from os import urandom
import crypto
from crypto.dh import DH

#https://tools.ietf.org/html/rfc4753#section-3.1

SUPPORTED_ECDH_GROUPS = [0xa];

class ECDHFactory():
	@staticmethod
	def get_ecdh(group):
		if group == 0x7:
			return ECDHNIST256();
		elif group == 0x8:
			return ECDHNIST384();
		elif group == 0x9:
			return ECDHNIST521();
		elif group == 0xa:
			return ECDHSECP160R1();
		else:
			raise Exception("Not implemented");

class ECDH(DH):
	ALG_ID = 0x0;
	
	def __init__(self):
		pass
	
	def get_component_length(self):
		return self.component_bit_length

	def generate_private_key(self):
		pass

	def generate_public_key(self):
		pass

	def compute_shared_secret(self):
		pass

	def encode_public_key(self):
		pass

	@staticmethod
	def decode_public_key(buffer):
		pass


"""
   https://tools.ietf.org/html/rfc5903#section-7
   In an ECP key exchange, the Diffie-Hellman public value passed in a
   KE payload consists of two components, x and y, corresponding to the
   coordinates of an elliptic curve point.  Each component MUST have bit
   length as given in the following table.

      Diffie-Hellman group                component bit length
      ------------------------            --------------------

      256-bit Random ECP Group                   256
      384-bit Random ECP Group                   384
      521-bit Random ECP Group                   528

   This length is enforced, if necessary, by prepending the value with
   zeros.

   The Diffie-Hellman public value is obtained by concatenating the x
   and y values.

   The Diffie-Hellman shared secret value consists of the x value of the
   Diffie-Hellman common value.

   These formats should be regarded as specific to ECP curves and may
   not be applicable to EC2N (elliptic curve group over GF[2^N]) curves.

"""
class ECDHSECP160R1(ECDH):
	ALG_ID = 0xa;
	def __init__(self):
		self.private_key_size = int(160/8);
		self.modulus = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF;
		self.group_order = 0x0100000000000000000001F4C8F927AED3CA752257;
		self.b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45;
		self.gx = 0x4A96B5688EF573284664698968C38BB913CBFC82;
		self.gy = 0x23A628553168947D59DCC912042351377AC5FB32;
		self.h = 0x1;
		self.a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC;
		self.G = misc.ECPoint(self.gx, self.gy);
		self.component_bit_length = 0x14;

	def get_component_length(self):
		return self.component_bit_length

	def set_private_key(self, key):
		self.private_key = key;

	def generate_private_key(self):
		self.private_key = misc.Math.bytes_to_int(bytearray(urandom(self.private_key_size)));

	def generate_public_key(self):
		self.public_key = misc.Math.double_and_add(self.G, self.private_key, self.a, self.b, self.modulus);
		return self.public_key;

	def compute_shared_secret(self, public_key):
		return misc.Math.double_and_add(public_key, self.private_key, self.a, self.b, self.modulus).x;

	def encode_public_key(self):
		x = misc.Math.int_to_bytes(self.public_key.get_x());
		if len(x) != self.component_bit_length:
			x = bytearray([0] * (self.component_bit_length - len(x))) + x;
		y = misc.Math.int_to_bytes(self.public_key.get_y());
		if len(y) != self.component_bit_length:
			y = bytearray([0] * (self.component_bit_length - len(y))) + y;
		return x + y;

	@staticmethod
	def decode_public_key(buffer):
		x = misc.Math.bytes_to_int(buffer[:int(len(buffer)/2)])
		y = misc.Math.bytes_to_int(buffer[int(len(buffer)/2):])
		return misc.ECPoint(x, y);

# https://tools.ietf.org/html/rfc5903#section-3

class ECDHNIST256(ECDH):
	ALG_ID = 0x7;
	def __init__(self):
		self.private_key_size = int(256/8);
		self.modulus = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
		self.group_order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
		self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
		self.gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296;
		self.gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5;
		#self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc;
		self.h = 0x1;
		self.a = -3;
		self.G = misc.ECPoint(self.gx, self.gy);
		self.component_bit_length = 0x20;

	def get_component_length(self):
		return self.component_bit_length

	def set_private_key(self, key):
		self.private_key = key;

	def generate_private_key(self):
		self.private_key = misc.Math.bytes_to_int(bytearray(urandom(self.private_key_size)));

	def generate_public_key(self):
		self.public_key = misc.Math.double_and_add(self.G, self.private_key, self.a, self.b, self.modulus);
		return self.public_key;

	def compute_shared_secret(self, public_key):
		return misc.Math.double_and_add(public_key, self.private_key, self.a, self.b, self.modulus).x;

	def encode_public_key(self):
		x = misc.Math.int_to_bytes(self.public_key.get_x());
		if len(x) != self.component_bit_length:
			x = bytearray([0] * (self.component_bit_length - len(x))) + x;
		y = misc.Math.int_to_bytes(self.public_key.get_y());
		if len(y) != self.component_bit_length:
			y = bytearray([0] * (self.component_bit_length - len(y))) + y;
		return x + y;

	@staticmethod
	def decode_public_key(buffer):
		x = misc.Math.bytes_to_int(buffer[:int(len(buffer)/2)])
		y = misc.Math.bytes_to_int(buffer[int(len(buffer)/2):])
		return misc.ECPoint(x, y);

class ECDHNIST384(ECDH):
	ALG_ID = 0x8;
	def __init__(self):
		self.private_key_size = int(384/8);
		self.modulus = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff;
		self.group_order = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973;
		self.b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef;
		self.gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7;
		self.gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f;
		#self.a = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc;
		self.h = 0x1;
		self.a = -3;
		self.G = misc.ECPoint(self.gx, self.gy);
		self.component_bit_length = 0x30;

	def get_component_length(self):
		return self.component_bit_length

	def set_private_key(self, key):
		self.private_key = key;

	def generate_private_key(self):
		self.private_key = misc.Math.bytes_to_int(bytearray(urandom(self.private_key_size)));

	def generate_public_key(self):
		self.public_key = misc.Math.double_and_add(self.G, self.private_key, self.a, self.b, self.modulus);
		return self.public_key;

	def compute_shared_secret(self, public_key):
		return misc.Math.double_and_add(public_key, self.private_key, self.a, self.b, self.modulus).x;

	def encode_public_key(self):
		x = misc.Math.int_to_bytes(self.public_key.get_x());
		if len(x) != self.component_bit_length:
			x = bytearray([0] * (self.component_bit_length - len(x))) + x;
		y = misc.Math.int_to_bytes(self.public_key.get_y());
		if len(y) != self.component_bit_length:
			y = bytearray([0] * (self.component_bit_length - len(y))) + y;
		return x + y;

	@staticmethod
	def decode_public_key(buffer):
		x = misc.Math.bytes_to_int(buffer[:int(len(buffer)/2)])
		y = misc.Math.bytes_to_int(buffer[int(len(buffer)/2):])
		return misc.ECPoint(x, y);

class ECDHNIST521(ECDH):
	ALG_ID = 0x9;
	def __init__(self):
		self.private_key_size = int(528/8);
		self.modulus = 0x000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
		self.group_order = 0x000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409;
		self.b = 0x00000051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00;
		self.gx = 0x000000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66;
		self.gy = 0x0000011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650;
		#self.a = 0x000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc;
		self.h = 0x1;
		self.a = -3;
		self.G = misc.ECPoint(self.gx, self.gy);
		self.component_bit_length = 0x42;

	def get_component_length(self):
		return self.component_bit_length

	def set_private_key(self, key):
		self.private_key = key;

	def generate_private_key(self):
		self.private_key = misc.Math.bytes_to_int(bytearray(urandom(self.private_key_size)));

	def generate_public_key(self):
		self.public_key = misc.Math.double_and_add(self.G, self.private_key, self.a, self.b, self.modulus);
		return self.public_key;

	def compute_shared_secret(self, public_key):
		return misc.Math.double_and_add(public_key, self.private_key, self.a, self.b, self.modulus).x;

	def encode_public_key(self):
		x = misc.Math.int_to_bytes(self.public_key.get_x());
		if len(x) != self.component_bit_length:
			x = bytearray([0] * (self.component_bit_length - len(x))) + x;
		y = misc.Math.int_to_bytes(self.public_key.get_y());
		if len(y) != self.component_bit_length:
			y = bytearray([0] * (self.component_bit_length - len(y))) + y;
		return x + y;

	@staticmethod
	def decode_public_key(buffer):
		x = misc.Math.bytes_to_int(buffer[:int(len(buffer)/2)])
		y = misc.Math.bytes_to_int(buffer[int(len(buffer)/2):])
		return misc.ECPoint(x, y);

class ECDHBrainpool256(ECDH):
	ALG_ID = 0x0;
	def __init__(self):
		self.private_key_size = int(256/8);
		self.modulus = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377;
		self.group_order = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7;
		self.b = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6;
		self.gx = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262;
		self.gy = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997;
		self.a = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9;
		self.h = 0x1;
		self.G = misc.ECPoint(self.gx, self.gy);
		self.component_bit_length = 0x20;

	def get_component_length(self):
		return self.component_bit_length;

	def set_private_key(self, key):
		self.private_key = key;

	def generate_private_key(self):
		self.private_key = misc.Math.bytes_to_int(bytearray(urandom(self.private_key_size)));

	def generate_public_key(self):
		self.public_key = misc.Math.double_and_add(self.G, self.private_key, self.a, self.b, self.modulus);
		return self.public_key;

	# The Diffie-Hellman shared secret value consists of the x value of the
	# Diffie-Hellman common value.
	# https://tools.ietf.org/html/rfc5903
	def compute_shared_secret(self, public_key):
		return misc.Math.double_and_add(public_key, self.private_key, self.a, self.b, self.modulus).x;

	def encode_public_key(self):
		x = misc.Math.int_to_bytes(self.public_key.get_x());
		if len(x) != self.component_bit_length:
			x = bytearray([0] * (self.component_bit_length - len(x))) + x;
		y = misc.Math.int_to_bytes(self.public_key.get_y());
		if len(y) != self.component_bit_length:
			y = bytearray([0] * (self.component_bit_length - len(y))) + y;
		return x + y;

	@staticmethod
	def decode_public_key(buffer):
		x = misc.Math.bytes_to_int(buffer[:int(len(buffer)/2)])
		y = misc.Math.bytes_to_int(buffer[int(len(buffer)/2):])
		return misc.ECPoint(x, y);