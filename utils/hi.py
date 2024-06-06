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

# Encoding of public key is described in 
# https://tools.ietf.org/html/rfc7401#section-3
# https://tools.ietf.org/html/rfc3110#section-2

import sys
import os
sys.path.append(os.getcwd())

import hiplib.utils
from hiplib.utils.misc import Math

"""
Base 64 encoding decoding routines
"""
from base64 import b64decode
from base64 import b64encode

# Logging
import logging

class HostID():

	HI_DSA = 0x3;
	HI_RSA = 0x5;
	HI_ECDSA = 0x7;
	HI_ECDSA_LOW = 0x9;

	def __init__(self):
		pass
	def to_byte_array(self):
		return None;
	def get_length(self):
		return 0;
	def get_algorithm(self):
		return 0x0;

# https://tools.ietf.org/html/rfc3110#section-2
class RSAHostID(HostID):
	def __init__(self, exponent = None, modulus = None):
		exponent_bytes = Math.int_to_bytes(exponent);
		modulus_bytes = Math.int_to_bytes(modulus);
		exponent_length = len(exponent_bytes);
		self.exponent_length_field_length = 0x1;
		if len(exponent_bytes) > 255:
			self.exponent_length_field_length = 0x3;
		self.buffer = bytearray([0] * (self.exponent_length_field_length + \
						len(exponent_bytes) + len(modulus_bytes)));
		offset = 0x1;
		if exponent_length > 255:
			self.buffer[1] = (exponent_length >> 8) & 0xFF;
			self.buffer[2] = (exponent_length) & 0xFF;
			offset = 0x3;
		else:
			self.buffer[0] = len(exponent_bytes);
		self.buffer[offset:offset + len(exponent_bytes)] = exponent_bytes;
		offset += len(exponent_bytes);
		self.buffer[offset:offset + len(modulus_bytes)] = modulus_bytes;

	@staticmethod
	def from_byte_buffer(buffer):
		offset = 0;
		if buffer[offset] == 0x0:
			exponent_length = (buffer[offset + 1] << 8) | buffer[offset + 2];
			offset = 0x3;
		else:
			exponent_length = buffer[offset];
			offset = 0x1;
		exponent = buffer[offset:offset + exponent_length];
		offset += exponent_length;
		modulus = buffer[offset:];
		return RSAHostID(Math.bytes_to_int(exponent), Math.bytes_to_int(modulus));

	def to_byte_array(self):
		return self.buffer;

	def get_length(self):
		return len(self.buffer);

	def get_exponent(self):
		offset = 0x1;
		if self.buffer[0] == 0x0:
			exponent_length = (self.buffer[1] << 8);
			exponent_length |= (self.buffer[2] & 0xFF);
			offset = 0x3;
		else:
			exponent_length = self.buffer[0];
		return Math.bytes_to_int(self.buffer[offset:offset + exponent_length]);

	def get_modulus(self):
		offset = 0x1;
		if self.buffer[0] == 0x0:
			exponent_length = (self.buffer[1] << 8);
			exponent_length |= (self.buffer[2] & 0xFF);
			offset = 0x3;
		else:
			exponent_length = self.buffer[0];
		return Math.bytes_to_int(self.buffer[offset + exponent_length:]);

	def get_algorithm(self):
		return self.HI_RSA;

class ECDSAHostID(HostID):

	NIST_P_256_CURVE_ID = 0x1;
	NIST_P_256_LENGTH = 0x20;
	NIST_P_384_CURVE_ID = 0x2;
	NIST_P_384_LENGTH = 0x30;

	UNCOMPRESSED_POINT = 0x4;

	def __init__(self, curve_id, x, y):
		self.x = Math.int_to_bytes(x);
		self.y = Math.int_to_bytes(y);
		if curve_id == ECDSAHostID.NIST_P_256_CURVE_ID:
			#if self.NIST_P_256_LENGTH - len(self.x) > 0:
			self.x = bytearray(([0] * (ECDSAHostID.NIST_P_256_LENGTH - len(self.x)))) + self.x;
			self.y = bytearray(([0] * (ECDSAHostID.NIST_P_256_LENGTH - len(self.y)))) + self.y;
		elif curve_id == ECDSAHostID.NIST_P_384_CURVE_ID:
			#if self.NIST_P_384_LENGTH - len(self.x) > 0:
			self.x = bytearray(([0] * (ECDSAHostID.NIST_P_384_LENGTH - len(self.x)))) + self.x;
			self.y = bytearray(([0] * (ECDSAHostID.NIST_P_384_LENGTH - len(self.y)))) + self.y;
		else:
			raise Exception("Unsupported curve");
		self.curve_id = bytearray([(curve_id >> 8) & 0xFF, curve_id & 0xFF]);
		self.compression = bytearray([ECDSAHostID.UNCOMPRESSED_POINT]);
		self.buffer = self.curve_id + self.compression + self.x + self.y;

	CURVE_ID_LENGTH = 0x2;
	POINT_OFFSET = 0x3;

	@staticmethod
	def from_byte_buffer(buffer):
		curve_id = (buffer[0] << 8) | buffer[1];
		compression = buffer[2] & 0xFF;
		if compression != ECDSAHostID.UNCOMPRESSED_POINT:
			raise Exception("Only uncompressed points are supported")
		if curve_id == ECDSAHostID.NIST_P_256_CURVE_ID:
			x = buffer[ECDSAHostID.POINT_OFFSET:ECDSAHostID.POINT_OFFSET + ECDSAHostID.NIST_P_256_LENGTH];
			y = buffer[ECDSAHostID.POINT_OFFSET + ECDSAHostID.NIST_P_256_LENGTH:];
		elif curve_id == ECDSAHostID.NIST_P_384_CURVE_ID:
			x = buffer[ECDSAHostID.POINT_OFFSET:ECDSAHostID.POINT_OFFSET + ECDSAHostID.NIST_P_384_LENGTH];
			y = buffer[ECDSAHostID.POINT_OFFSET + ECDSAHostID.NIST_P_384_LENGTH:];
		else:
			raise Exception("Unsupported curve");
		return ECDSAHostID(curve_id, Math.bytes_to_int(x), Math.bytes_to_int(y));

	def to_byte_array(self):
		return self.buffer;

	def get_length(self):
		return len(self.buffer);

	def get_curve_id(self):
		return self.curve_id[0] << 8 | self.curve_id[1];

	def get_x(self):
		#return self.x;
		return Math.bytes_to_int(self.x);

	def get_y(self):
		#return self.y;
		return Math.bytes_to_int(self.y);

	def get_algorithm(self):
		return self.HI_ECDSA;

class ECDSALowHostID(HostID):
	SECP160R1_LENGTH = 0x14;
	SECP160R1_CURVE_ID = 0x1;
	UNCOMPRESSED_POINT = 0x4;

	def __init__(self, curve_id, x, y):
		self.x = Math.int_to_bytes(x);
		self.y = Math.int_to_bytes(y);
		if curve_id == ECDSALowHostID.SECP160R1_CURVE_ID:
			#if self.SECP160R1_LENGTH - len(self.x) > 0:
			self.x = bytearray(([0] * (ECDSALowHostID.SECP160R1_LENGTH - len(self.x)))) + self.x;
			self.y = bytearray(([0] * (ECDSALowHostID.SECP160R1_LENGTH - len(self.y)))) + self.y;
		else:
			raise Exception("Unsupported curve");
		self.curve_id = bytearray([(curve_id >> 8) & 0xFF, curve_id & 0xFF]);
		self.compression = bytearray([ECDSALowHostID.UNCOMPRESSED_POINT]);
		#self.buffer = self.curve_id + self.x + self.y;
		self.buffer = self.curve_id + self.compression + self.x + self.y;

	CURVE_ID_LENGTH = 0x2;
	POINT_OFFSET = 0x3;
	@staticmethod
	def from_byte_buffer(buffer):
		curve_id = (buffer[0] << 8) | buffer[1];
		compression = buffer[2] & 0xFF;
		if compression != ECDSALowHostID.UNCOMPRESSED_POINT:
			raise Exception("Only uncompressed points are supported")
		if curve_id == ECDSALowHostID.SECP160R1_CURVE_ID:
			x = buffer[ECDSALowHostID.POINT_OFFSET:ECDSALowHostID.POINT_OFFSET + ECDSALowHostID.SECP160R1_LENGTH];
			y = buffer[ECDSALowHostID.POINT_OFFSET + ECDSALowHostID.SECP160R1_LENGTH:];
		#elif curve_id == ECDSALowHostID.NIST_P_384_CURVE_ID:
		#	x = buffer[ECDSALowHostID.CURVE_ID_LENGTH:ECDSALowHostID.CURVE_ID_LENGTH + ECDSALowHostID.SECP160R1_LENGTH];
		#	y = buffer[ECDSALowHostID.CURVE_ID_LENGTH + ECDSALowHostID.SECP160R1_LENGTH:];
		else:
			raise Exception("Unsupported curve");
		return ECDSALowHostID(curve_id, Math.bytes_to_int(x), Math.bytes_to_int(y));

	def to_byte_array(self):
		return self.buffer;

	def get_length(self):
		return len(self.buffer);

	def get_curve_id(self):
		return self.curve_id[0] << 8 | self.curve_id[1];

	def get_x(self):
		#return self.x;
		return Math.bytes_to_int(self.x);

	def get_y(self):
		#return self.y;
		return Math.bytes_to_int(self.y);

	def get_algorithm(self):
		return self.HI_ECDSA_LOW;