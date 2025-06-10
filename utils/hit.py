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
sys.path.append(os.getcwd());

import logging

import crypto
from binascii import unhexlify
from binascii import hexlify
from crypto import digest


HIP_HIT_CONTEX_ID     = bytearray(unhexlify('F0EFF02FBFF43D0FE7930C3C6E6174EA'))
TRUNCATED_HASH_LENGTH = 0x0C;
OGA_OFFSET            = 0x03;

class HIT():
	
	SHA256_OGA = 0x1;
	SHA384_OGA = 0x2;
	SHA1_OGA = 0x3;

	def __init__(self):
		pass

	@staticmethod
	def get_responders_hash_algorithm(rhit):
		oga_id = rhit[OGA_OFFSET] & 0x0F;
		if oga_id == 0x1:
			rhash = digest.SHA256Digest();
		elif oga_id == 0x2:
			rhash = digest.SHA384Digest();
		elif oga_id == 0x3:
			rhash = digest.SHA1Digest();
		else:
			raise Exception("Unknwon hash algorithm");
		return rhash; 

	@staticmethod
	def get_responders_oga_id(rhit):
		return rhit[OGA_OFFSET] & 0x0F;

	@staticmethod
	def bytearray_to_int(b):
		int_value = 0;
		for i in range(0, len(b)):
			int_value = (b[i] << ((len(b) - i - 1)*8)) | int_value;
		return int_value;

	@staticmethod
	def int_to_bytearray(v, length):
		b = [];
		for i in range(length - 1, -1, -1):
			b += [(v >> (i*8)) & 0xFF]
		return b;

	@staticmethod
	def encode_96(bytestring):
		# Size of the byte array
		length = len(bytestring) * 8;
		# Offset from the begining
		length = int((length - TRUNCATED_HASH_LENGTH * 8) / 2);
		v = HIT.bytearray_to_int(bytestring);
		# This is probably not needed
		mask = (1 << (TRUNCATED_HASH_LENGTH * 8)) - 1;
		result = (v >> length) & mask;
		#result = (v >> length);
		return bytearray(HIT.int_to_bytearray(result, TRUNCATED_HASH_LENGTH));

	@staticmethod
	def get(hi, oga_id):
		rhash = None
		if oga_id == 0x1:
			rhash = digest.SHA256Digest();
		elif oga_id == 0x2:
			rhash = digest.SHA384Digest();
		elif oga_id == 0x3:
			rhash = digest.SHA1Digest();
		else:
			raise Exception("Unknwon hash algorithm");
		"""
		Input      :=  any bitstring
		OGA ID     :=  4-bit Orchid Generation Algorithm identifier
		Hash Input :=  Context ID | Input
		Hash       :=  Hash_function( Hash Input )
		ORCHID     :=  Prefix | OGA ID | Encode_96( Hash )
		"""
		HIP_HIT_PREFIX = bytearray(unhexlify("20010010"));
		HIP_HIT_PREFIX[len(HIP_HIT_PREFIX) - 1] = HIP_HIT_PREFIX[len(HIP_HIT_PREFIX) - 1] | (oga_id & 0xF);
		encoded_hit = HIT.encode_96(rhash.digest(HIP_HIT_CONTEX_ID + hi))
		return HIP_HIT_PREFIX + encoded_hit;

	@staticmethod
	def get_hex(hi, oga_id):
		return hexlify(HIT.get(hi, oga_id)).decode("ascii");

	@staticmethod
	def get_hex_formated(hi, oga_id):
		hit_hex = HIT.get_hex(hi, oga_id);
		#print(hit_hex)
		hit_formated = "";
		for i in range(0, len(hit_hex), 4):
			hit_formated += hit_hex[i] + hit_hex[i + 1] + hit_hex[i + 2] + hit_hex[i + 3] + ":";
		return hit_formated.rstrip(":");

	@staticmethod
	def get_oga_id(hit):
		"""
		Derives OGA ID from the HIT
		"""
		return hit[OGA_OFFSET] & 0xF;

	@staticmethod
	def get_rhash(hit):
		"""
		Returns RHash instance
		"""
		oga_id = HIT.get_oga_id();
		rhash = None
		if oga_id == 0x1:
			rhash = digest.SHA256Digest();
		elif oga_id == 0x2:
			rhash = digest.SHA384Digest();
		elif oga_id == 0x3:
			rhash = digest.SHA1Digest();
		else:
			raise Exception("Unknwon hash algorithm");
		return rhash;
