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

sys.path.append("../");

from utils.misc import Math

"""
Base 64 encoding decoding routines
"""
from base64 import b64decode
from base64 import b64encode

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
	def __init__(self, exponent, modulus):
		exponent_bytes = Math.int_to_bytes(exponent);
		modulus_bytes = Math.int_to_bytes(modulus);
		exponent_length = len(exponent_bytes);
		self.exponent_length_field_length = 0x1;
		if len(exponent_bytes) > 255:
			self.exponent_length_field_length = 0x3;
		self.buffer = bytearray([0] * (self.exponent_length_field_length + \
						len(exponent_bytes) + len(modulus_bytes)));
		offset = 0x1;
		if exponent > 255:
			self.buffer[1] = (exponent_length >> 8) & 0xFF;
			self.buffer[2] = (exponent_length) & 0xFF;
			offset = 0x3;
		else:
			self.buffer[0] = len(exponent_bytes);
		self.buffer[offset:offset + len(exponent_bytes)] = exponent_bytes;
		offset += len(exponent_bytes);
		self.buffer[offset:offset + len(modulus_bytes)] = modulus_bytes;

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
		return self.buffer[offset:offset + exponent_length];

	def get_modulus(self):
		offset = 0x1;
		if self.buffer[0] == 0x0:
			exponent_length = (self.buffer[1] << 8);
			exponent_length |= (self.buffer[2] & 0xFF);
			offset = 0x3;
		else:
			exponent_length = self.buffer[0];
		return self.buffer[offset + exponent_length:];

	def get_algorithm(self):
		return self.HI_RSA;

#from crypto.asymmetric import RSAPublicKey
#pubkey = RSAPublicKey.load_pem("../config/public.pem");
#hi_ = RSAHostID(pubkey.get_public_exponent(), pubkey.get_modulus());
#from hit import HIT
#print(HIT.get_hex_formated(hi_.to_byte_array(), HIT.SHA256_OGA));
