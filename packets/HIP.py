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

# https://tools.ietf.org/html/rfc7401

import logging

import copy

#import sys
#import os
#sys.path.append(os.getcwd() + "/..")

#import utils
#from utils.misc import Math

HIP_TLV_TYPE_OFFSET              = 0x0;
HIP_TLV_CRITICAL_BIT_OFFSET      = 0x0;
HIP_TLV_LENGTH_OFFSET            = 0x2;

HIP_TLV_LENGTH_LENGTH            = 0x2;
HIP_TLV_TYPE_LENGTH              = 0x2;
HIP_TLV_CRITICAL_BIT_LENGHT      = 0x1;

HIP_PROTOCOL                     = 0x8B;
HIP_IPPROTO_NONE                 = 0x3B;

HIP_VERSION                      = 0x2;

HIP_HEADER_LENGTH                = 0x28;
HIP_TLV_LENGTH                   = 0x4;

HIP_DEFAULT_PACKET_LENGTH        = 0x4;

HIP_FRAGMENT_LENGTH              = 0x578;

class HIPParameter():
	def __init__(self, buffer = None):
		self.buffer = buffer;
	def get_type(self):
		return (self.buffer[HIP_TLV_TYPE_OFFSET] << 8 | self.buffer[HIP_TLV_TYPE_OFFSET + 1])
	def set_type(self, type):
		self.buffer[HIP_TLV_TYPE_OFFSET] = (type >> 8) & 0xFF;
		self.buffer[HIP_TLV_TYPE_OFFSET + 1] = (type & 0xFF);
	def get_critical_bit(self):
		return (self.buffer[HIP_TLV_CRITICAL_BIT_OFFSET] & 0x1);
	def get_length(self):
		return (self.buffer[HIP_TLV_LENGTH_OFFSET] << 8 | self.buffer[HIP_TLV_LENGTH_OFFSET + 1]);
	def set_length(self, length):
		self.buffer[HIP_TLV_LENGTH_OFFSET] = (length >> 8) & 0xFF;
		self.buffer[HIP_TLV_LENGTH_OFFSET + 1] = (length & 0xFF);
	def get_byte_buffer(self):
		return copy.deepcopy(self.buffer);

HIP_R1_COUNTER_OFFSET            = 0x8;

HIP_R1_COUNTER_TYPE              = 0x81;
HIP_R1_COUNTER_LENGTH            = 0x0C;
HIP_R1_COUNTER_RESERVED_LENGTH   = 0x4;
HIP_R1_GENERATION_COUNTER_LENGTH = 0x8;

class R1CounterParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH + 
				HIP_R1_COUNTER_RESERVED_LENGTH +
				HIP_R1_GENERATION_COUNTER_LENGTH
				));
			self.set_type(HIP_R1_COUNTER_TYPE);
			self.set_length(HIP_R1_COUNTER_LENGTH);

	def get_counter(self):
		"""
		Returns the counter of the R1 parameter
		"""
		return (self.buffer[HIP_R1_COUNTER_OFFSET] << 56 |
			self.buffer[HIP_R1_COUNTER_OFFSET + 1] << 48 |  
			self.buffer[HIP_R1_COUNTER_OFFSET + 2] << 40 |
			self.buffer[HIP_R1_COUNTER_OFFSET + 3] << 32 |
			self.buffer[HIP_R1_COUNTER_OFFSET + 4] << 24 |
			self.buffer[HIP_R1_COUNTER_OFFSET + 5] << 16 |
			self.buffer[HIP_R1_COUNTER_OFFSET + 6] << 8  |
			self.buffer[HIP_R1_COUNTER_OFFSET + 7]);

	def set_counter(self, counter):
		"""
		Sets the counter of the R1 parameter
		"""
		self.buffer[HIP_R1_COUNTER_OFFSET] = (counter >> 56) & 0xFF;
		self.buffer[HIP_R1_COUNTER_OFFSET + 1] = (counter >> 48) & 0xFF;
		self.buffer[HIP_R1_COUNTER_OFFSET + 2] = (counter >> 40) & 0xFF;
		self.buffer[HIP_R1_COUNTER_OFFSET + 3] = (counter >> 32) & 0xFF;
		self.buffer[HIP_R1_COUNTER_OFFSET + 4] = (counter >> 24) & 0xFF;
		self.buffer[HIP_R1_COUNTER_OFFSET + 5] = (counter >> 16) & 0xFF;
		self.buffer[HIP_R1_COUNTER_OFFSET + 6] = (counter >> 8) & 0xFF;
		self.buffer[HIP_R1_COUNTER_OFFSET + 7] = (counter) & 0xFF;

HIP_PUZZLE_TYPE                  = 257;
#HIP_PUZZLE_LENGTH                = 4 + int(R_HASH_VALUE_LENGTH / 8);

HIP_PUZZLE_K_OFFSET              = 0x4;
HIP_PUZZLE_LIFETIME_OFFSET       = 0x5;
HIP_PUZZLE_OPAQUE_OFFSET         = 0x6;
HIP_PUZZLE_RANDOM_I_OFFSET       = 0x8;

HIP_PUZZLE_K_LENGTH              = 0x1;
HIP_PUZZLE_LIFETIME_LENGTH       = 0x1;
HIP_PUZZLE_OPAQUE_LENGTH         = 0x2;
#HIP_PUZZLE_RANDOM_I_LENGTH       = int(R_HASH_VALUE_LENGTH / 8);

class PuzzleParameter(HIPParameter):
	def __init__(self, buffer = None, rhash_length = 0x20):

		self.HIP_PUZZLE_RANDOM_I_LENGTH = rhash_length;
		self.HIP_PUZZLE_LENGTH = 4 + rhash_length;

		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH + 
				HIP_PUZZLE_K_LENGTH +
				HIP_PUZZLE_LIFETIME_LENGTH +
				HIP_PUZZLE_OPAQUE_LENGTH + 
				self.HIP_PUZZLE_RANDOM_I_LENGTH
				));
			self.set_type(HIP_PUZZLE_TYPE);
			self.set_length(self.HIP_PUZZLE_LENGTH);
	def get_k_value(self):
		return self.buffer[HIP_PUZZLE_K_OFFSET] & 0xFF;
	def set_k_value(self, k):
		self.buffer[HIP_PUZZLE_K_OFFSET] = k & 0xFF;
	def get_lifetime(self):
		return self.buffer[HIP_PUZZLE_LIFETIME_OFFSET] & 0xFF;
	def set_lifetime(self, lifetime):
		self.buffer[HIP_PUZZLE_LIFETIME_OFFSET] = lifetime & 0xFF;
	def get_opaque(self):
		return self.buffer[HIP_PUZZLE_OPAQUE_OFFSET:HIP_PUZZLE_OPAQUE_OFFSET + 2];
	def set_opaque(self, opaque):
		self.buffer[HIP_PUZZLE_OPAQUE_OFFSET:HIP_PUZZLE_OPAQUE_OFFSET + 2] = opaque;
	def get_random(self, rhash_length = 0x20):
		self.HIP_PUZZLE_RANDOM_I_LENGTH = rhash_length;
		self.HIP_PUZZLE_LENGTH = 4 + rhash_length;
		return (self.buffer[HIP_PUZZLE_RANDOM_I_OFFSET:
				HIP_PUZZLE_RANDOM_I_OFFSET + self.HIP_PUZZLE_RANDOM_I_LENGTH]);
	def set_random(self, random, rhash_length):
		self.HIP_PUZZLE_RANDOM_I_LENGTH = rhash_length;
		self.HIP_PUZZLE_LENGTH = 4 + rhash_length;
		self.buffer[HIP_PUZZLE_RANDOM_I_OFFSET:HIP_PUZZLE_RANDOM_I_OFFSET + self.HIP_PUZZLE_RANDOM_I_LENGTH] = random;

HIP_SOLUTION_TYPE                              = 321;


HIP_SOLUTION_RANDOM_I_OFFSET                   = 0x8;
#HIP_SOLUTION_RANDOM_I_LENGTH                   = int(R_HASH_VALUE_LENGTH / 8);

HIP_SOLUTION_K_LENGTH                          = 0x1;
HIP_SOLUTION_K_OFFSET                          = 0x4;

#HIP_SOLUTION_J_OFFSET                          = 0x8 + int(R_HASH_VALUE_LENGTH / 8);
#HIP_SOLUTION_J_LENGTH                          = int(R_HASH_VALUE_LENGTH / 8);

#HIP_SOLUTION_LENGTH                            = 0x4 + int(R_HASH_VALUE_LENGTH / 4);
HIP_SOLUTION_RESERVED_LENGTH                   = 0x1;
HIP_SOLUTION_RESERVED_OFFSET                   = 0x5;

HIP_SOLUTION_OPAQUE_LENGTH                     = 0x2;
HIP_SOLITION_OPAQUE_OFFSET                     = 0x6;

class SolutionParameter(HIPParameter):
	def __init__(self, buffer = None, rhash_length = 0x20):
		self.buffer = buffer;
		self.HIP_SOLUTION_RANDOM_I_LENGTH = rhash_length;
		self.HIP_SOLUTION_J_OFFSET = HIP_SOLUTION_RANDOM_I_OFFSET + rhash_length;
		self.HIP_SOLUTION_J_LENGTH = rhash_length;
		self.HIP_SOLUTION_LENGTH = 4 + rhash_length * 2;

		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH + 
				HIP_SOLUTION_K_LENGTH +
				HIP_SOLUTION_RESERVED_LENGTH +
				HIP_SOLUTION_OPAQUE_LENGTH + 
				self.HIP_SOLUTION_RANDOM_I_LENGTH + 
				self.HIP_SOLUTION_J_LENGTH
				));
			self.set_type(HIP_SOLUTION_TYPE);
			self.set_length(self.HIP_SOLUTION_LENGTH);
	def get_k_value(self):
		return self.buffer[HIP_SOLUTION_K_OFFSET] & 0xFF;
	def set_k_value(self, k):
		self.buffer[HIP_SOLUTION_K_OFFSET] = k & 0xFF;
	def get_opaque(self):
		return self.buffer[HIP_SOLITION_OPAQUE_OFFSET:HIP_SOLITION_OPAQUE_OFFSET + 2];
	def set_opaque(self, opaque):
		self.buffer[HIP_SOLITION_OPAQUE_OFFSET:HIP_SOLITION_OPAQUE_OFFSET + 2] = opaque;
	def get_random(self, rhash_length = 0x20):
		self.HIP_SOLUTION_RANDOM_I_LENGTH = rhash_length;
		self.HIP_SOLUTION_J_OFFSET = HIP_SOLUTION_RANDOM_I_OFFSET + rhash_length;
		self.HIP_SOLUTION_J_LENGTH = rhash_length;
		self.HIP_SOLUTION_LENGTH = 4 + rhash_length * 2;
		return (self.buffer[HIP_SOLUTION_RANDOM_I_OFFSET:HIP_SOLUTION_RANDOM_I_OFFSET + self.HIP_SOLUTION_RANDOM_I_LENGTH]);
	def set_random(self, random, rhash_length = 0x20):
		self.HIP_SOLUTION_RANDOM_I_LENGTH = rhash_length;
		self.HIP_SOLUTION_J_OFFSET = HIP_SOLUTION_RANDOM_I_OFFSET + rhash_length;
		self.HIP_SOLUTION_J_LENGTH = rhash_length;
		self.HIP_SOLUTION_LENGTH = 4 + rhash_length * 2;
		self.buffer[HIP_SOLUTION_RANDOM_I_OFFSET:HIP_SOLUTION_RANDOM_I_OFFSET + self.HIP_SOLUTION_RANDOM_I_LENGTH] = random;
	def get_solution(self, rhash_length = 0x20):
		self.HIP_SOLUTION_RANDOM_I_LENGTH = rhash_length;
		self.HIP_SOLUTION_J_OFFSET = HIP_SOLUTION_RANDOM_I_OFFSET + rhash_length;
		self.HIP_SOLUTION_J_LENGTH = rhash_length;
		self.HIP_SOLUTION_LENGTH = 4 + rhash_length * 2;
		return (self.buffer[self.HIP_SOLUTION_J_OFFSET:self.HIP_SOLUTION_J_OFFSET + self.HIP_SOLUTION_J_LENGTH]);
	def set_solution(self, solution, rhash_length = 0x20):
		self.HIP_SOLUTION_RANDOM_I_LENGTH = rhash_length;
		self.HIP_SOLUTION_J_OFFSET = HIP_SOLUTION_RANDOM_I_OFFSET + rhash_length;
		self.HIP_SOLUTION_J_LENGTH = rhash_length;
		self.HIP_SOLUTION_LENGTH = 4 + rhash_length * 2;
		self.buffer[self.HIP_SOLUTION_J_OFFSET:self.HIP_SOLUTION_J_OFFSET + self.HIP_SOLUTION_J_LENGTH] = solution;

HIP_DH_GROUP_LIST_TYPE              = 0x1FF;
HIP_DH_GROUP_LIST_OFFSET            = 0x4;

class DHGroupListParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_DH_GROUP_LIST_TYPE);
			self.set_length(0);
	def add_groups(self, groups):
		self.set_length(len(groups));
		self.buffer += bytearray(groups);
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_groups(self):
		groups = [];
		length = self.get_length();
		has_more_groups = True;
		counter = 0;
		while has_more_groups:
			groups.append(self.buffer[HIP_DH_GROUP_LIST_OFFSET + counter] & 0xFF);
			counter += 1;
			if counter >= length:
				has_more_groups = False;
		return groups;

HIP_DH_TYPE                         = 0x201;
HIP_DH_GROUP_ID_OFFSET              = 0x4;
HIP_PUBLIC_VALUE_LENGTH_OFFSET      = 0x5;
HIP_PUBLIC_VALUE_OFFSET             = 0x7;

HIP_GROUP_ID_LENGTH                 = 0x1;
HIP_PUBLIC_VALUE_LENGTH_LENGTH      = 0x2;

class DHParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH +
				HIP_GROUP_ID_LENGTH +
				HIP_PUBLIC_VALUE_LENGTH_LENGTH
				));
			self.set_type(HIP_DH_TYPE);
			self.set_length(HIP_GROUP_ID_LENGTH + HIP_PUBLIC_VALUE_LENGTH_LENGTH);
	def get_group_id(self):
		return self.buffer[HIP_DH_GROUP_ID_OFFSET];
	def set_group_id(self, group_id):
		self.buffer[HIP_DH_GROUP_ID_OFFSET] = group_id;
	def get_public_value_length(self):
		return (self.buffer[HIP_PUBLIC_VALUE_LENGTH_OFFSET] << 8 | self.buffer[HIP_PUBLIC_VALUE_LENGTH_OFFSET + 1])
	def set_public_value_length(self, public_value_length):
		self.buffer[HIP_PUBLIC_VALUE_LENGTH_OFFSET] = ((public_value_length << 8) & 0xFF)
		self.buffer[HIP_PUBLIC_VALUE_LENGTH_OFFSET + 1] = (public_value_length & 0xFF)
	def add_public_value(self, public_value):
		dh_public_value_length = self.get_public_value_length();
		if dh_public_value_length != 0x0:
			raise Exception("DH public key was already set");
		length = self.get_length();
		self.buffer += public_value;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
		length = len(public_value) + HIP_GROUP_ID_LENGTH + HIP_PUBLIC_VALUE_LENGTH_LENGTH + padding;
		self.set_length(length);
		self.set_public_value_length(int(len(public_value) / 8));
		
	def get_public_value(self):
		public_value_length = self.get_public_value_length() * 8;
		return self.buffer[HIP_PUBLIC_VALUE_OFFSET:HIP_PUBLIC_VALUE_OFFSET + public_value_length]

HIP_CIPHER_TYPE                     = 0x243;
HIP_CIPHER_LIST_OFFSET              = 0x4;

class CipherParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_CIPHER_TYPE);
			self.set_length(0);
	def add_ciphers(self, ciphers):
		length = self.get_length();
		if length > 0:
			raise Exception("Ciphers were set");
		self.set_length(len(ciphers) * 2);
		for cipher in ciphers:
			cipher_id = bytearray([0] * 2);
			cipher_id[0] = (cipher >> 8) & 0xFF;
			cipher_id[1] = cipher & 0xFF;
			self.buffer += cipher_id;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_ciphers(self):
		ciphers = [];
		length = self.get_length();
		has_more_ciphers = True;
		counter = 0;
		while has_more_ciphers:
			ciphers.append((self.buffer[HIP_CIPHER_LIST_OFFSET + counter] << 8) | 
				self.buffer[HIP_CIPHER_LIST_OFFSET + counter + 1]);
			counter += 2;
			if counter >= length:
				has_more_ciphers = False;
		return ciphers;

HIP_HI_TYPE                 = 0x2C1;

HIP_HI_LENGTH_LENGTH        = 0x2;
HIP_DI_LENGTH_LENGTH        = 0x2;
HIP_ALGORITHM_LENGTH        = 0x2;

HIP_HI_LENGTH_OFFSET        = 0x4;
HIP_DI_LENGTH_OFFSET        = 0x6;
HIP_ALGORITHM_OFFSET        = 0x8;
HIP_HI_OFFSET               = 0xa;

class HostIdParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH +
				HIP_HI_LENGTH_LENGTH +
				HIP_DI_LENGTH_LENGTH +
				HIP_ALGORITHM_LENGTH
				));
			self.set_type(HIP_HI_TYPE);
			self.set_length(
				HIP_HI_LENGTH_LENGTH + 
				HIP_DI_LENGTH_LENGTH +
				HIP_ALGORITHM_LENGTH);
	def set_hi_length(self, length):
		self.buffer[HIP_HI_LENGTH_OFFSET] = (length >> 8) & 0xFF;
		self.buffer[HIP_HI_LENGTH_OFFSET + 1] = length & 0xFF;
	def get_hi_length(self):
		return ((self.buffer[HIP_HI_LENGTH_OFFSET] << 8) |
				self.buffer[HIP_HI_LENGTH_OFFSET + 1]);
	def set_di_length(self, length):
		self.buffer[HIP_DI_LENGTH_OFFSET] = (length >> 8) & 0xF;
		self.buffer[HIP_DI_LENGTH_OFFSET + 1] = length & 0xFF;
	def get_di_length(self):
		return (((self.buffer[HIP_DI_LENGTH_OFFSET] << 8) & 0xF) |
				self.buffer[HIP_DI_LENGTH_OFFSET + 1]);
	def get_di_type(self):
		return (self.buffer[HIP_DI_LENGTH_OFFSET] >> 4) & 0xF;
	def set_di_type(self, type):
		self.buffer[HIP_DI_LENGTH_OFFSET] = (type << 4) | self.buffer[HIP_DI_LENGTH_OFFSET];
	def set_algorithm(self, algorithm):
		self.buffer[HIP_ALGORITHM_OFFSET] = ((algorithm >> 8) & 0xFF);
		self.buffer[HIP_ALGORITHM_OFFSET + 1] = (algorithm & 0xFF);
	def get_algorithm(self):
		return (self.buffer[HIP_ALGORITHM_OFFSET] << 8 | self.buffer[HIP_ALGORITHM_OFFSET + 1]);
	def set_domain_id(self, di):
		di_length = di.get_length();
		hi_length = self.get_hi_length();
		if hi_length == 0:
			raise Exception("HI was not set");
		offset = HIP_HI_OFFSET + hi_length;
		self.buffer[offset:offset + di_length] = di.to_byte_array();
		self.set_di_length(di_length);
		self.set_di_type(di.get_type());
		length = self.get_length() + di_length;
		self.set_length(length);
		self.buffer += bytearray([0] * ((8 - len(self.buffer) % 8) % 8));
	def set_host_id(self, hi):
		hi_length = self.get_hi_length();
		if hi_length > 0:
			raise Exception("HI was already set");
		logging.debug(list(hi.to_byte_array()));
		self.buffer[HIP_HI_OFFSET:HIP_HI_OFFSET + hi.get_length()] = hi.to_byte_array();
		self.set_hi_length(hi.get_length());
		self.set_algorithm(hi.get_algorithm());
		length = self.get_length() + hi.get_length();
		self.set_length(length);
	def get_domain_id(self):
		di_length = self.get_di_length();
		hi_length = self.get_hi_length();
		offset = HIP_HI_OFFSET + self.get_hi_length();
		return self.buffer[offset:offset + di_length];
	def get_host_id(self):
		hi_length = self.get_hi_length();
		if hi_length == 0:
			raise Exception("HI was not set yet");
		return self.buffer[HIP_HI_OFFSET:HIP_HI_OFFSET + hi_length];

HIP_HIT_SUITS_TYPE               = 0x2CB;
HIP_HIT_SUITS_OFFSET             = 0x4;

class HITSuitListParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_HIT_SUITS_TYPE);
			self.set_length(0);
	def add_suits(self, suits):
		length = self.get_length();
		if length > 0:
			raise Exception("Suits were set already");
		self.set_length(len(suits));
		self.buffer += bytearray(suits);
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_suits(self):
		suits = [];
		length = self.get_length();
		return self.buffer[HIP_HIT_SUITS_OFFSET:HIP_HIT_SUITS_OFFSET + length];

HIP_TRANSPORT_FORMAT_LIST_TYPE      = 0x801;
HIP_TRANSPORT_FORMAT_LIST_OFFSET    = 0x4;

class TransportListParameter(HIPParameter):

	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_TRANSPORT_FORMAT_LIST_TYPE);
			self.set_length(0);

	def add_transport_formats(self, transport_formats):
		length = self.get_length();
		if length > 0:
			raise Exception("Transport format list was set");
		self.set_length(len(transport_formats) * 2);
		for transport_format in transport_formats:
			transport_format_id = bytearray([0] * 2);
			transport_format_id[0] = (transport_format >> 8) & 0xFF;
			transport_format_id[1] = transport_format & 0xFF;
			self.buffer += transport_format_id;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);

	def get_transport_formats(self):
		transport_formats = [];
		length = self.get_length();
		has_more_transport_formats = True;
		counter = 0;
		while has_more_transport_formats:
			transport_formats.append((self.buffer[HIP_TRANSPORT_FORMAT_LIST_OFFSET + counter] << 8) | 
				self.buffer[HIP_TRANSPORT_FORMAT_LIST_OFFSET + counter + 1]);
			counter += 2;
			if counter >= length:
				has_more_transport_formats = False;
		return transport_formats;

HIP_MAC_TYPE      = 0xF041;
HIP_MAC_OFFSET    = 0x4;

class MACParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_MAC_TYPE);
			self.set_length(0);
	def get_hmac(self):
		length = self.get_length();
		return self.buffer[HIP_MAC_OFFSET:HIP_MAC_OFFSET + length];
	def set_hmac(self, hmac):
		self.set_length(len(hmac));
		length = len(hmac);
		self.buffer[HIP_MAC_OFFSET:HIP_MAC_OFFSET + length] = hmac;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);

HIP_MAC_2_TYPE    = 0xF081;
HIP_MAC_2_OFFSET  = 0x4;

class MAC2Parameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_MAC_2_TYPE);
			self.set_length(0);
	def get_hmac(self):
		length = self.get_length();
		return self.buffer[HIP_MAC_2_OFFSET:HIP_MAC_2_OFFSET + length];
	def set_hmac(self, hmac):
		self.set_length(len(hmac));
		length = len(hmac);
		self.buffer[HIP_MAC_2_OFFSET:HIP_MAC_2_OFFSET + length] = hmac;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);

HIP_SIG_TYPE             = 0xF101;
HIP_SIG_ALG_TYPE_OFFSET  = 0x4;
HIP_SIG_OFFSET           = 0x6;

HIP_SIG_ALG_TYPE_LENGTH  = 0x2;

class SignatureParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH + 
				HIP_SIG_ALG_TYPE_LENGTH
				));
			self.set_type(HIP_SIG_TYPE);
			self.set_length(0);

	def set_signature_algorithm(self, alg):
		self.buffer[HIP_SIG_ALG_TYPE_OFFSET] = (alg >> 0x8) & 0xFF;
		self.buffer[HIP_SIG_ALG_TYPE_OFFSET + 1] = (alg & 0xFF);

	def get_signature_algorithn(self):
		return (self.buffer[HIP_SIG_ALG_TYPE_OFFSET] << 0x8) + \
			self.buffer[HIP_SIG_ALG_TYPE_OFFSET + 1] & 0xFF;

	def get_signature(self):
		length = self.get_length();
		return self.buffer[HIP_SIG_OFFSET:HIP_SIG_OFFSET + length - HIP_SIG_ALG_TYPE_LENGTH];
	def set_signature(self, sig):
		self.set_length(len(sig) + HIP_SIG_ALG_TYPE_LENGTH);
		length = len(sig);
		self.buffer[HIP_SIG_OFFSET:HIP_SIG_OFFSET + length] = sig;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);

HIP_SIG_2_TYPE           = 0xF0C1;
HIP_SIG_ALG_TYPE_OFFSET  = 0x4;
HIP_SIG_OFFSET           = 0x6;

HIP_SIG_ALG_TYPE_LENGTH  = 0x2;

class Signature2Parameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH + 
				HIP_SIG_ALG_TYPE_LENGTH
				));
			self.set_type(HIP_SIG_2_TYPE);
			self.set_length(0);

	def set_signature_algorithm(self, alg):
		self.buffer[HIP_SIG_ALG_TYPE_OFFSET] = (alg >> 0x8) & 0xFF;
		self.buffer[HIP_SIG_ALG_TYPE_OFFSET + 1] = (alg & 0xFF);

	def get_signature_algorithn(self):
		return (self.buffer[HIP_SIG_ALG_TYPE_OFFSET] << 0x8) +  \
			self.buffer[HIP_SIG_ALG_TYPE_OFFSET + 1] & 0xFF;
	
	def get_signature(self):
		length = self.get_length();
		return self.buffer[HIP_SIG_OFFSET:HIP_SIG_OFFSET + length - HIP_SIG_ALG_TYPE_LENGTH];
	
	def set_signature(self, sig):
		self.set_length(len(sig) + HIP_SIG_ALG_TYPE_LENGTH);
		length = len(sig);
		self.buffer[HIP_SIG_OFFSET:HIP_SIG_OFFSET + length] = sig;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);

HIP_SEQ_TYPE             = 0x181;
HIP_UPDATE_ID_OFFSET     = 0x4;

HIP_UPDATE_ID_LENGTH     = 0x4;

class SequenceParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH + 
				HIP_UPDATE_ID_LENGTH
				));
			self.set_type(HIP_SEQ_TYPE);
			self.set_length(HIP_UPDATE_ID_LENGTH);
	def get_id(self):
		return ((self.buffer[HIP_UPDATE_ID_OFFSET] << 24) |
			(self.buffer[HIP_UPDATE_ID_OFFSET + 1] << 16) |
			(self.buffer[HIP_UPDATE_ID_OFFSET + 2] << 8)  |
			self.buffer[HIP_UPDATE_ID_OFFSET + 3]);
	def set_id(self, id):
		self.buffer[HIP_UPDATE_ID_OFFSET] = (id >> 24) & 0xFF;
		self.buffer[HIP_UPDATE_ID_OFFSET + 1] = (id >> 16) & 0xFF;
		self.buffer[HIP_UPDATE_ID_OFFSET + 2] = (id >> 8) & 0xFF;
		self.buffer[HIP_UPDATE_ID_OFFSET + 3] = id & 0xFF;

HIP_ACK_TYPE             = 0x1C1;
HIP_UPDATE_ID_OFFSET     = 0x4;

class AckParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_ACK_TYPE);
			self.set_length(0);
	def set_ids(self, ids):
		self.set_length(len(ids) * HIP_UPDATE_ID_LENGTH);
		offset = HIP_UPDATE_ID_OFFSET;
		for id in ids:
			self.buffer += bytearray([0] * HIP_UPDATE_ID_LENGTH);
			self.buffer[offset] = (id << 24) & 0xFF;
			self.buffer[offset + 1] = (id << 16) & 0xFF;
			self.buffer[offset + 2] = (id << 8) & 0xFF;
			self.buffer[offset + 3] = (id & 0xFF);
			offset += HIP_UPDATE_ID_LENGTH;
	def get_ids(self):
		length = self.get_length();
		has_more_update_ids = (length > 0);
		counter = 0;
		ids = [];
		while has_more_update_ids:
			ids.append(
				(self.buffer[HIP_UPDATE_ID_OFFSET + counter] >> 24) |
				(self.buffer[HIP_UPDATE_ID_OFFSET + counter + 1] >> 16) |
				(self.buffer[HIP_UPDATE_ID_OFFSET + counter + 2] >> 8) |
				(self.buffer[HIP_UPDATE_ID_OFFSET + counter + 3])
				)
			counter += 4;
			if counter >= length:
				has_more_update_ids = False;
		return ids;

HIP_ENCRYPTED_TYPE             = 0x281;
HIP_ENCRYPTED_RESERVED_LENGTH  = 0x4;

HIP_ENCRYPTED_IV_OFFSET        = 0x8;

class EncryptedParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH +
				HIP_ENCRYPTED_RESERVED_LENGTH
				));
			self.set_type(HIP_ENCRYPTED_TYPE);
			self.set_length(HIP_ENCRYPTED_RESERVED_LENGTH);
	def add_iv(self, iv_length, iv):
		if len(self.buffer) != (HIP_TLV_LENGTH_LENGTH + 
			HIP_TLV_TYPE_LENGTH + 
			HIP_ENCRYPTED_RESERVED_LENGTH):
			raise Exception("IV was already set");
		offset = HIP_ENCRYPTED_IV_OFFSET;
		self.buffer += bytearray([0] * iv_length);
		self.buffer[offset:offset + iv_length] = iv;
		length = self.get_length();
		length += len(iv);
		self.set_length(length);

	def get_iv(self, iv_length):
		if len(self.buffer) == (HIP_TLV_LENGTH_LENGTH + 
			HIP_TLV_TYPE_LENGTH + 
			HIP_ENCRYPTED_RESERVED_LENGTH):
			raise Exception("IV was not set yet");
		offset = HIP_ENCRYPTED_IV_OFFSET;
		return self.buffer[offset:offset + iv_length];

	def add_encrypted_data(self, iv_length, enc_data):
		if len(self.buffer) == (HIP_TLV_LENGTH_LENGTH + 
			HIP_TLV_TYPE_LENGTH + 
			HIP_ENCRYPTED_RESERVED_LENGTH):
			raise Exception("IV was not set yet");
		offset = HIP_ENCRYPTED_IV_OFFSET + iv_length;
		padding = len(enc_data) % 4;
		self.buffer += bytearray([0] * (len(enc_data) + padding));
		self.buffer[offset:offset + len(enc_data)] = enc_data;
		length = self.get_length();
		length += len(enc_data);
		self.set_length(length);
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_encrypted_data(self, iv_length):
		if len(self.buffer) <= (
			HIP_TLV_LENGTH_LENGTH + 
			HIP_TLV_TYPE_LENGTH + 
			HIP_ENCRYPTED_RESERVED_LENGTH + 
			iv_length):
			raise Exception("IV was not set yet");
		length = self.get_length();
		offset = HIP_ENCRYPTED_IV_OFFSET + iv_length;
		enc_data_length = length - HIP_ENCRYPTED_RESERVED_LENGTH - iv_length;
		return self.buffer[offset:offset + enc_data_length];


HIP_NOTIFICATION_TYPE             = 0x281;
HIP_NOTIFICATION_RESERVED_LENGTH  = 0x2;
HIP_NOTIFY_DATA_TYPE_LENGTH       = 0x2;

HIP_NOTIFICATION_RESERVED_OFFSET  = 0x4;
HIP_NOTIFY_MESSAGE_TYPE_OFFSET    = 0x6;
HIP_NOTIFICATION_DATA_OFFSET      = 0x8;

# Error messages
UNSUPPORTED_CRITICAL_PARAMETER_TYPE = 0x1;
INVALID_SYNTAX = 0x7;
NO_DH_PROPOSAL_CHOSEN = 0xE;
INVALID_DH_CHOSEN = 0xF;
NO_HIP_PROPOSAL_CHOSEN = 0x10;
INVALID_HIP_CIPHER_CHOSEN = 0x11;
UNSUPPORTED_HIT_SUITE = 0x14;
AUTHENTICATION_FAILED = 0x18;
CHECKSUM_FAILED = 0x1A;
HIP_MAC_FAILED = 0x1C;
ENCRYPTION_FAILED = 0x20;
INVALID_HIT = 0x28;
BLOCKED_BY_POLICY = 0x2a;
RESPONDER_BUSY_PLEASE_RETRY = 0x2c;
I2_ACKNOWLEDGEMENT = 0x4000;

class NotificationParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH +
				HIP_NOTIFICATION_RESERVED_LENGTH +
				HIP_NOTIFY_DATA_TYPE_LENGTH
				));
			self.set_type(HIP_NOTIFICATION_TYPE);
			self.set_length(HIP_NOTIFICATION_RESERVED_LENGTH + HIP_NOTIFY_DATA_TYPE_LENGTH);
	def get_notify_message_type(self):
		return (self.buffer[HIP_NOTIFY_MESSAGE_TYPE_OFFSET] << 8) | (self.buffer[HIP_NOTIFY_MESSAGE_TYPE_OFFSET + 1]);
	def set_notify_message_type(self, type):
		self.buffer[HIP_NOTIFY_MESSAGE_TYPE_OFFSET] = (type >> 8);
		self.buffer[HIP_NOTIFY_MESSAGE_TYPE_OFFSET] = (type & 0xFF);
	def get_notification_data(self):
		length = self.get_length();
		if length > HIP_NOTIFICATION_RESERVED_LENGTH + HIP_NOTIFY_DATA_TYPE_LENGTH:
			raise Exception("Notification data was already set");
		offset = HIP_NOTIFICATION_DATA_OFFSET;
		data_boundary = length - HIP_NOTIFICATION_RESERVED_LENGTH - HIP_NOTIFY_DATA_TYPE_LENGTH;
		return self.buffer[offset:offset + data_boundary];
	def set_notification_data(self, data):
		length = self.get_length();
		if length > HIP_NOTIFICATION_RESERVED_LENGTH + HIP_NOTIFY_DATA_TYPE_LENGTH:
			raise Exception("Notification data was already set");
		padding = 4 - len(data) % 4;
		offset = HIP_NOTIFICATION_DATA_OFFSET;
		self.buffer += bytearray([0] * (len(data) + padding));
		self.buffer[offset:offset + len(data)] = data;
		self.set_length(length + len(data));
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);


HIP_ECHO_REQUEST_SIGNED_TYPE             = 0x381;

HIP_ECHO_REQUEST_SIGNED_OFFSET           = 0x4;

class EchoRequestSignedParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_ECHO_REQUEST_SIGNED_TYPE);
			self.set_length(0);
	def add_opaque_data(self, data):
		self.set_length(len(data));
		self.buffer += data;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_opaque_data(self):
		length = self.get_length();
		return self.buffer[HIP_ECHO_REQUEST_SIGNED_OFFSET:HIP_ECHO_REQUEST_SIGNED_OFFSET + length]

HIP_ECHO_REQUEST_UNSIGNED_TYPE             = 0xF8AD;
HIP_ECHO_REQUEST_UNSIGNED_OFFSET           = 0x4;

class EchoRequestUnsignedParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_ECHO_REQUEST_UNSIGNED_TYPE);
			self.set_length(0);
	def add_opaque_data(self, data):
		self.set_length(len(data));
		self.buffer += data;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_opaque_data(self):
		length = self.get_length();
		return self.buffer[HIP_ECHO_REQUEST_UNSIGNED_OFFSET:HIP_ECHO_REQUEST_UNSIGNED_OFFSET + length]

HIP_ECHO_RESPONSE_SIGNED_TYPE             = 0x3C1;

HIP_ECHO_RESPONSE_SIGNED_OFFSET           = 0x4;

class EchoResponseSignedParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_ECHO_RESPONSE_SIGNED_TYPE);
			self.set_length(0);
	def add_opaque_data(self, data):
		self.set_length(len(data));
		self.buffer += data;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_opaque_data(self):
		length = self.get_length();
		return self.buffer[HIP_ECHO_RESPONSE_SIGNED_OFFSET:HIP_ECHO_RESPONSE_SIGNED_OFFSET + length]

HIP_ECHO_RESPONSE_UNSIGNED_TYPE             = 0xF7C1;

HIP_ECHO_RESPONSE_UNSIGNED_OFFSET           = 0x4;

class EchoResponseUnsignedParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH
				));
			self.set_type(HIP_ECHO_RESPONSE_UNSIGNED_TYPE);
			self.set_length(0);
	def add_opaque_data(self, data):
		self.set_length(len(data));
		self.buffer += data;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_opaque_data(self):
		length = self.get_length();
		return self.buffer[HIP_ECHO_RESPONSE_UNSIGNED_OFFSET:HIP_ECHO_RESPONSE_UNSIGNED_OFFSET + length]


HIP_ESP_TRANSFORM_TYPE              = 0xFFF;
HIP_SUITS_LIST_OFFSET               = 0x4;
HIP_SUITS_RESERVED_LENGTH           = 0x2;

class ESPTransformParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH + 
				HIP_SUITS_RESERVED_LENGTH
				));
			self.set_type(HIP_ESP_TRANSFORM_TYPE);
			self.set_length(HIP_SUITS_RESERVED_LENGTH);
	def add_suits(self, suits):
		self.set_length((len(suits) + 1) * 2);
		for suit in suits:
			suit_id = bytearray([0] * 2);
			suit_id[0] = (suit >> 8) & 0xFF;
			suit_id[1] = suit & 0xFF;
			self.buffer += suit_id;
		padding = (8 - len(self.buffer) % 8) % 8;
		self.buffer += bytearray([0] * padding);
	def get_suits(self):
		suits = [];
		length = self.get_length();
		has_more_suits = True;
		counter = 2;
		while has_more_suits:
			suits.append((self.buffer[HIP_SUITS_LIST_OFFSET + counter] << 8) | 
				self.buffer[HIP_SUITS_LIST_OFFSET + counter + 1]);
			counter += 2;
			if counter >= length:
				has_more_suits = False;
		return suits;

HIP_ESP_INFO_TYPE                   = 0x41;
HIP_ESP_INFO_RESERVED_LENGTH        = 0x2;
HIP_ESP_INFO_KEYMAT_INDEX_LENGTH    = 0x2;
HIP_ESP_INFO_KEYMAT_INDEX_OFFSET    = 0x6;
HIP_ESP_INFO_OLD_SPI_LENGTH         = 0x4;
HIP_ESP_INFO_OLD_SPI_OFFSET         = 0x8;
HIP_ESP_INFO_NEW_SPI_LENGTH         = 0x4;
HIP_ESP_INFO_NEW_SPI_OFFSET         = 0xC;

class ESPInfoParameter(HIPParameter):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = bytearray([0] * (
				HIP_TLV_LENGTH_LENGTH + 
				HIP_TLV_TYPE_LENGTH +
				HIP_ESP_INFO_RESERVED_LENGTH +
				HIP_ESP_INFO_KEYMAT_INDEX_LENGTH +
				HIP_ESP_INFO_OLD_SPI_LENGTH +
				HIP_ESP_INFO_NEW_SPI_LENGTH
				));
			self.set_type(HIP_ESP_INFO_TYPE);
			self.set_length(
				HIP_ESP_INFO_RESERVED_LENGTH +
				HIP_ESP_INFO_KEYMAT_INDEX_LENGTH +
				HIP_ESP_INFO_OLD_SPI_LENGTH +
				HIP_ESP_INFO_NEW_SPI_LENGTH);
	def set_keymat_index(self, keymat_index):
		self.buffer[HIP_ESP_INFO_KEYMAT_INDEX_OFFSET] = (keymat_index >> 8) & 0xFF;
		self.buffer[HIP_ESP_INFO_KEYMAT_INDEX_OFFSET + 1] = (keymat_index & 0xFF);
	def get_keymat_index(self):
		return (self.buffer[HIP_ESP_INFO_KEYMAT_INDEX_OFFSET] << 8) | self.buffer[HIP_ESP_INFO_KEYMAT_INDEX_OFFSET + 1];
	def set_old_spi(self, spi):
		self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET] = (spi >> 24) & 0xFF;
		self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET + 1] = (spi >> 16) & 0xFF;
		self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET + 2] = (spi >> 8) & 0xFF;
		self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET + 3] = (spi & 0xFF);
	def get_old_spi(self):
		return ((self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET] << 24) |
			(self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET + 1] << 16) |
			(self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET + 2] << 8) |
			(self.buffer[HIP_ESP_INFO_OLD_SPI_OFFSET + 3]));
	def set_new_spi(self, spi):
		self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET] = (spi >> 24) & 0xFF;
		self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET + 1] = (spi >> 16) & 0xFF;
		self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET + 2] = (spi >> 8) & 0xFF;
		self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET + 3] = (spi & 0xFF);
	def get_new_spi(self):
		return ((self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET] << 24) |
			(self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET + 1] << 16) |
			(self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET + 2] << 8) |
			(self.buffer[HIP_ESP_INFO_NEW_SPI_OFFSET + 3]));

HIP_NEXT_HEADER_OFFSET           = 0x0;
HIP_HEADER_LENGTH_OFFSET         = 0x1;
HIP_PACKET_TYPE_OFFSET           = 0x2;
HIP_PACKET_VERSION_OFFSET        = 0x3;
HIP_CHECKSUM_OFFSET              = 0x4;
HIP_CONTROLS_OFFSET              = 0x6;
HIP_SENDERS_HIT_OFFSET           = 0x8;
HIP_RECIEVERS_HIT_OFFSET         = 0x18;
HIP_PARAMETERS_OFFSET            = 0x28;

HIP_NEXT_HEADER_LENGTH           = 0x1;
HIP_HEADER_LENGHT_LENGTH         = 0x1;
HIP_PACKET_TYPE_LENGTH           = 0x1;
HIP_VERSION_LENGTH               = 0x1;
HIP_CHECKSUM_LENGTH              = 0x2;
HIP_CONTROLS_LENGTH              = 0x2;
HIP_SENDERS_HIT_LENGTH           = 0x10;
HIP_RECIEVERS_HIT_LENGTH         = 0x10;

HIP_FIXED_HEADER_LENGTH_EXCL_8_BYTES = 32;

HIP_I1_PACKET                    = 0x1;
HIP_R1_PACKET                    = 0x2;
HIP_I2_PACKET                    = 0x3;
HIP_R2_PACKET                    = 0x4;
HIP_UPDATE_PACKET                = 0x10;
HIP_NOTIFY_PACKET                = 0x11;
HIP_CLOSE_PACKET                 = 0x12;
HIP_CLOSE_ACK_PACKET             = 0x13;

"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Checksum             |           Controls            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Sender's Host Identity Tag (HIT)               |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Receiver's Host Identity Tag (HIT)              |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                        HIP Parameters                         /
   /                                                               /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
class HIPPacket():
	def __init__(self, buffer = None):
		if not buffer:
			self.buffer = bytearray([0] * (
					HIP_NEXT_HEADER_LENGTH +
					HIP_HEADER_LENGHT_LENGTH + 
					HIP_PACKET_TYPE_LENGTH + 
					HIP_VERSION_LENGTH +
					HIP_CHECKSUM_LENGTH +
					HIP_CONTROLS_LENGTH +
					HIP_SENDERS_HIT_LENGTH +
					HIP_RECIEVERS_HIT_LENGTH));
			self.set_length(int(HIP_FIXED_HEADER_LENGTH_EXCL_8_BYTES / 8));
		else:
			self.buffer = buffer;

	def get_next_header(self):
		return self.buffer[HIP_NEXT_HEADER_OFFSET];
	def set_next_header(self, next_header):
		self.buffer[HIP_NEXT_HEADER_OFFSET] = next_header;
	def get_length(self):
		return self.buffer[HIP_HEADER_LENGTH_OFFSET];
	def set_length(self, header_length):
		self.buffer[HIP_HEADER_LENGTH_OFFSET] = header_length; 
	def get_packet_type(self):
		return self.buffer[HIP_PACKET_TYPE_OFFSET] & 0x7F;
	def set_packet_type(self, packet_type):
		self.buffer[HIP_PACKET_TYPE_OFFSET] = packet_type & 0x7F;
	def get_version(self):
		return (self.buffer[HIP_PACKET_VERSION_OFFSET] >> 0x4) & 0xFF;
	def set_version(self, version):
		self.buffer[HIP_PACKET_VERSION_OFFSET] = 0x1;
		self.buffer[HIP_PACKET_VERSION_OFFSET] = (version << 4) | self.buffer[HIP_PACKET_VERSION_OFFSET];
	def get_checksum(self):
		return ((self.buffer[HIP_CHECKSUM_OFFSET] << 0x8) | self.buffer[HIP_CHECKSUM_OFFSET + 1]);
	def set_checksum(self, checksum):
		self.buffer[HIP_CHECKSUM_OFFSET] = (checksum >> 8) & 0xFF;
		self.buffer[HIP_CHECKSUM_OFFSET + 1] = (checksum & 0xFF);
	def get_controls(self):
		return ((self.buffer[HIP_CONTROLS_OFFSET] << 0x8) | self.buffer[HIP_CONTROLS_OFFSET + 1]);
	def set_controls(self, controls):
		self.buffer[HIP_CONTROLS_OFFSET] = (controls >> 8) & 0xFF;
		self.buffer[HIP_CONTROLS_OFFSET + 1] = (controls & 0xFF);
	def get_senders_hit(self):
		return self.buffer[HIP_SENDERS_HIT_OFFSET:HIP_SENDERS_HIT_OFFSET + HIP_SENDERS_HIT_LENGTH];
	def set_senders_hit(self, hit):
		self.buffer[HIP_SENDERS_HIT_OFFSET:HIP_SENDERS_HIT_OFFSET + HIP_SENDERS_HIT_LENGTH] = hit;
	def get_receivers_hit(self):
		return self.buffer[HIP_RECIEVERS_HIT_OFFSET:HIP_RECIEVERS_HIT_OFFSET + HIP_RECIEVERS_HIT_LENGTH];
	def set_receivers_hit(self, hit):
		self.buffer[HIP_RECIEVERS_HIT_OFFSET:HIP_RECIEVERS_HIT_OFFSET + HIP_RECIEVERS_HIT_LENGTH] = hit;
	def get_parameters(self):
		parameters = [];
		offset = HIP_PARAMETERS_OFFSET;
		has_more_parameters = False;
		length = self.get_length() * 8 + 8;
		if length > HIP_FIXED_HEADER_LENGTH_EXCL_8_BYTES:
			has_more_parameters = True;
		if length != len(self.buffer):
			# Invalid HIP packet
			return [];
		while has_more_parameters:
			param_type = (self.buffer[offset] << 8) | self.buffer[offset + 1]; 
			param_length = (self.buffer[offset + 2] << 8) | self.buffer[offset + 3];
			total_param_length = 11 + param_length - (param_length + 3) % 8;
			param_data = self.buffer[offset:offset + total_param_length];
			if param_type == HIP_R1_COUNTER_TYPE:
				parameters.append(R1CounterParameter(param_data));
			elif param_type == HIP_PUZZLE_TYPE:
				parameters.append(PuzzleParameter(param_data));
			elif param_type == HIP_SOLUTION_TYPE:
				parameters.append(SolutionParameter(param_data));
			elif param_type == HIP_DH_GROUP_LIST_TYPE:
				parameters.append(DHGroupListParameter(param_data));
			elif param_type == HIP_DH_TYPE:
				parameters.append(DHParameter(param_data));
			elif param_type == HIP_CIPHER_TYPE:
				parameters.append(CipherParameter(param_data));
			elif param_type == HIP_ESP_TRANSFORM_TYPE:
				parameters.append(ESPTransformParameter(param_data));
			elif param_type == HIP_ESP_INFO_TYPE:
				parameters.append(ESPInfoParameter(param_data));
			elif param_type == HIP_HI_TYPE:
				parameters.append(HostIdParameter(param_data));
			elif param_type == HIP_HIT_SUITS_TYPE:
				parameters.append(HITSuitListParameter(param_data));
			elif param_type == HIP_TRANSPORT_FORMAT_LIST_TYPE:
				parameters.append(TransportListParameter(param_data));
			elif param_type == HIP_MAC_TYPE:
				parameters.append(MACParameter(param_data));
			elif param_type == HIP_MAC_2_TYPE:
				parameters.append(MAC2Parameter(param_data));
			elif param_type == HIP_SIG_TYPE:
				parameters.append(SignatureParameter(param_data));
			elif param_type == HIP_SIG_2_TYPE:
				parameters.append(Signature2Parameter(param_data));
			elif param_type == HIP_SEQ_TYPE:
				parameters.append(SequenceParameter(param_data));
			elif param_type == HIP_ACK_TYPE:
				parameters.append(AckParameter(param_data));
			elif param_type == HIP_ENCRYPTED_TYPE:
				parameters.append(EncryptedParameter(param_data));
			elif param_type == HIP_NOTIFICATION_TYPE:
				parameters.append(NotificationParameter(param_data));
			elif param_type == HIP_ECHO_REQUEST_SIGNED_TYPE:
				parameters.append(EchoRequestSignedParameter(param_data));
			elif param_type == HIP_ECHO_REQUEST_UNSIGNED_TYPE:
				parameters.append(EchoRequestUnsignedParameter(param_data));
			elif param_type == HIP_ECHO_RESPONSE_SIGNED_TYPE:
				parameters.append(EchoResponseSignedParameter(param_data));
			elif param_type == HIP_ECHO_RESPONSE_UNSIGNED_TYPE:
				parameters.append(EchoResponseUnsignedParameter(param_data));
			offset += total_param_length;
			if offset >= length:
				has_more_parameters = False;
		return parameters;

	def get_buffer(self):
		return self.buffer;

class I1Packet(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_I1_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));

class R1Packet(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_R1_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));

class I2Packet(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_I2_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));

class R2Packet(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_R2_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));

class UpdatePacket(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_UPDATE_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));

class NotifyPacket(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_NOTIFY_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));

class ClosePacket(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_CLOSE_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));

class CloseAckPacket(HIPPacket):
	def __init__(self, buffer = None):
		super().__init__(buffer);
		self.set_packet_type(HIP_CLOSE_ACK_PACKET);
		self.set_length(int((HIP_HEADER_LENGTH - 8) / 8));
	def add_parameter(self, param):
		length = self.get_length() * 8;
		self.buffer += param.get_byte_buffer();
		length += len(param.get_byte_buffer());
		self.set_length(int(length / 8));
