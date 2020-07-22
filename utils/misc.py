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

import sys
import os
sys.path.append(os.getcwd())

from math import log, ceil, floor
from binascii import hexlify
import logging
from os import urandom

#print(sys.modules);

class ECPoint():
	def __init__(self, x, y):
		self.x = x;
		self.y = y;
	def __str__(self):
		return hex(self.x) + ", " + hex(self.y)
	def get_x(self):
		return self.x;
	def get_y(self):
		return self.y;
	def add(self, P, a, b, modulus):
		if isinstance(self, ECPointInf) and isinstance(P, ECPointInf):
			return ECPointInf();
		elif isinstance(self, ECPointInf):
			return ECPoint(P.get_x(), P.get_y());
		elif isinstance(P, ECPointInf):
			return ECPoint(self.get_x(), self.get_y());
		if P.get_x() == self.x and P.get_y() == self.y:
			y1 = self.y;
			x1 = self.x;
			t = Math.mul_inverse((2*y1) % modulus, modulus);
			beta = ((3*x1*x1 + a) * t) % modulus;
			x3 = (beta*beta - 2*x1) % modulus;
			y3 = (beta * (x1-x3) - y1) % modulus;
			return ECPoint(x3, y3);
		elif P.get_x() == self.x and P.get_y() == -self.y:
			return ECPointInf();
		elif P.get_x() != self.x or P.get_y() != self.y:
			y1 = self.y;
			x1 = self.x;
			y2 = P.get_y();
			x2 = P.get_x();
			t1 = Math.mul_inverse(x2 - x1, modulus);
			beta = ((y2 - y1) * t1) % modulus;
			x3 = (beta*beta - x1 - x2) % modulus;
			y3 = (beta * (x1-x3) - y1) % modulus;
			return ECPoint(x3, y3);

class ECPointInf(ECPoint):
	def __init__(self):
		self.x = 0;
		self.y = 0;
	def get_x(self):
		return self.x;
	def get_y(self):
		return self.y;
	def add(self, P, a, b, modulus):
		if isinstance(P, ECPointInf):
			return ECPointInf();
		return ECPoint(P.get_x(), P.get_y());

class Math():

	@staticmethod
	def int_to_bytes(number):
		length = int(ceil(Math.num_bits(number) / 8));
		byte_array = [];
		for i in range(length - 1, -1, -1):
			byte_array.append((number >> (i*8)) & 0xFF);
		#byte_array.reverse();
		return bytearray(byte_array);

	@staticmethod
	def bytes_to_int(bytes):
		result = 0;
		for i in range(len(bytes) - 1, -1, -1):
			result += bytes[(len(bytes) - 1) - i] << (8*i);
		return result;

	@staticmethod
	def num_bits(n):
		return floor(log(n, 2)) + 1;

	@staticmethod
	def to_bit_array(n, reverse = True):
		bitarray = [];
		while n > 0:
			r = n & 0x1;
			n = n >> 1;
			bitarray.append(r);
		if reverse:
			bitarray.reverse();
		return bitarray;

	@staticmethod
	def square_and_multiply(base, power, modulus):
		bits = Math.to_bit_array(power, False);
		result = base;
		for i in range(len(bits) - 1, 0, -1):
			result = (result * result) % modulus;
			if bits[i - 1] == 1:
				result = (result * base) % modulus;
		return result
		# 5 = 1*2^2 + 0*2^1 + 1*2^0
		#   = (1*2+0)*2 + 1
		#   = ((x^1)^2*x^0)^2*x^1
		# r = ((x^2)*1)^2*x
		# 4 = 1*2^2 + 0*2^0 + 1*2^0
		# r = ((x^2)*1)^2*1

	@staticmethod
	def double_and_add(G, k, a, b, modulus):
		bits = Math.to_bit_array(k, False);
		P = ECPointInf();
		Q = G;
		for i in range(0, len(bits)):
			if bits[i] == 1:
				P = P.add(Q, a, b, modulus);
			Q = Q.add(Q, a, b, modulus);
		# 5 = 101
		# P = G Q = 2G
		# P = G Q = 4G
		# P = 5G Q = 8G
		# 10 = 1010
		# P = 0 Q = 2G
		# P = 2G Q = 4G
		# P = 2G Q = 8G
		# P = 10G Q = 16G
		return P;

	@staticmethod
	def compress_point(G):
		return (G.get_x() << 8) | ((G.get_y() % 0x2) & 0xFF)

	@staticmethod
	def mul_inverse(n, modulus):
		a0 = n;
		b0 = modulus;
		t0 = 0;
		t = 1;
		s0 = 1;
		s = 0;
		q = a0 // b0;
		r = a0 % b0;
		while r > 0:
			temp = t0 - q*t;
			t0 = t;
			t = temp;
			temp = s0 - q*s;
			s0 = s;
			s = temp;
			a0 = b0;
			b0 = r;
			q= a0 // b0;
			r = a0 - q*b0;
		r = b0;
		return (s % modulus);

	@staticmethod
	def is_coprime(a, b):
		return gcd(a, b) == 1;

	@staticmethod
	def gcd(a, b):
		while b != 0:
			t = a % b;
			a = b;
			b = t;
		# a = 7, b = 4
		# a = 4, b = 3
		# a = 3, b = 1
		# a = 1, b = 0
		return a;

import crypto
from crypto.factory import HMACFactory, SymmetricCiphersFactory

class Utils():
	"""
	Various utilities
	"""
	@staticmethod
	def hits_equal(hit1, hit2):
		"""
		Checks if two Host Identity Tags are equal
		"""
		if len(hit1) != len(hit2):
			return False;
		for i in range(0, len(hit1)):
			if hit1[i] != hit2[i]:
				return False;
		return True;
		
	@staticmethod
	def ipv6_bytes_to_hex(address_bytes):
		"""
		Converts IPv6 bytes to a hexidecimal string
		"""
		return hexlify(address_bytes).decode("ascii");

	@staticmethod
	def ipv4_bytes_to_string(address_bytes):
		if len(address_bytes) != 0x4:
			return "";
		return str(address_bytes[0]) + "." + \
			str(address_bytes[1]) + "." + \
			str(address_bytes[2]) + "." + \
			str(address_bytes[3]);

	@staticmethod
	def ipv6_to_bytes(address):
		pass

	@staticmethod
	def ipv6_bytes_to_hex_formatted(address_bytes):
		"""
		Converts IPv6 bytes to a formatted string
		"""
		address = Utils.ipv6_bytes_to_hex(address_bytes);
		formatted = "";
		c = 1;
		for h in address:
			formatted += h;
			if c % 4 == 0:
				formatted += ":"
			c += 1;
		return formatted.rstrip(":");

	@staticmethod
	def ipv4_to_int(address):
		"""
		Converts IPv4 address to integer
		"""
		try:
			parts = address.split(".");
			address_as_int = 0;
			address_as_int |= (int(parts[0]) << 24);
			address_as_int |= (int(parts[1]) << 16);
			address_as_int |= (int(parts[2]) << 8);
			address_as_int |= (int(parts[3]));
			return address_as_int
		except:
			return 0;
	# https://tools.ietf.org/html/rfc7401#section-5.1.1
	# https://bazaar.launchpad.net/~hipl-core/hipl/trunk/view/head:/libcore/checksum.c
	@staticmethod
	def hip_ipv4_checksum(src, dst, protocol, length, data):
		s = 0;
		for i in range(0, len(data), 2):
			s += (((data[i] << 8) & 0xFF00) + (data[i + 1] & 0xFF));
		for i in range(0, 4, 2):
			s += (((src[i] << 8) & 0xFF00) + (src[i + 1] & 0xFF));
		for i in range(0, 4, 2):
			s += (((dst[i] << 8) & 0xFF00) + (dst[i + 1] & 0xFF));
		s = s + protocol + length;
		while (s >> 16):
			s = (s & 0xFFFF) + (s >> 16);
		return ~s & 0xFFFF;

	@staticmethod
	def generate_random(length):
		return urandom(length);

	@staticmethod
	def compute_keymat_length(hmac_alg, cipher_alg):
		hmac = HMACFactory.get(hmac_alg, None);
		cipher  = SymmetricCiphersFactory.get(cipher_alg);
		return 10 * (hmac.LENGTH + cipher.KEY_SIZE_BITS);

	@staticmethod
	def compute_hip_keymat_length(hmac_alg, cipher_alg):
		hmac = HMACFactory.get(hmac_alg, None);
		cipher  = SymmetricCiphersFactory.get(cipher_alg);
		return 2 * (hmac.LENGTH + cipher.KEY_SIZE_BITS);

	@staticmethod
	def get_keys(keymat, hmac_alg, cipher_alg, ihit_bytes, rhit_bytes):
		offset = 0;
		ihit = Math.bytes_to_int(ihit_bytes);
		rhit = Math.bytes_to_int(rhit_bytes);

		hmac = HMACFactory.get(hmac_alg, None);
		cipher  = SymmetricCiphersFactory.get(cipher_alg);
		if ihit < rhit:
			offset += (hmac.LENGTH + cipher.KEY_SIZE_BITS);
		return (keymat[offset: offset + cipher.KEY_SIZE_BITS], \
			keymat[offset + cipher.KEY_SIZE_BITS: offset + cipher.KEY_SIZE_BITS + hmac.LENGTH]);

	@staticmethod
	def get_keys_esp(keymat, keymat_index, hmac_alg, cipher_alg, ihit_bytes, rhit_bytes):
		
		ihit = Math.bytes_to_int(ihit_bytes);
		rhit = Math.bytes_to_int(rhit_bytes);

		hmac = HMACFactory.get(hmac_alg, None);
		cipher  = SymmetricCiphersFactory.get(cipher_alg);
		
		#offset = 2*(hmac.LENGTH + cipher.KEY_SIZE_BITS);
		offset = keymat_index;
		if ihit > rhit:
			offset += (hmac.LENGTH + cipher.KEY_SIZE_BITS);
		return (keymat[offset: offset + cipher.KEY_SIZE_BITS], \
			keymat[offset + cipher.KEY_SIZE_BITS: offset + cipher.KEY_SIZE_BITS + hmac.LENGTH]);

	@staticmethod
	def sort_hits(ihit_bytes, rhit_bytes):
		ihit = Math.bytes_to_int(ihit_bytes);
		rhit = Math.bytes_to_int(rhit_bytes);
		if ihit > rhit:
			return rhit_bytes + ihit_bytes;
		else:
			return ihit_bytes + rhit_bytes;

	@staticmethod
	def is_hit_smaller(ihit_bytes, rhit_bytes):
		ihit = Math.bytes_to_int(ihit_bytes);
		rhit = Math.bytes_to_int(rhit_bytes);
		if ihit < rhit:
			return True;
		else:
			return False;

	# https://tools.ietf.org/html/rfc5869
	# Key derivation function
	@staticmethod
	def kdf(alg, salt, ikm, info, l_octets):
		rhash = HMACFactory.get(alg, salt);
		prk   = rhash.digest(ikm);
		rhash = HMACFactory.get(alg, prk);
		n     = ceil(l_octets / rhash.LENGTH);
		okm   = bytearray([]);
		T     = bytearray([]);
		for i in range(1, n + 1):
			T = rhash.digest(T + info + bytearray([i]));
			okm += T;
		return okm[:l_octets];

		


