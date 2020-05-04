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
sys.path.append(os.getcwd() + "/..")

import crypto

from crypto.ecdh import ECDHSECP160R1, ECDHNIST521, ECDHNIST384, ECDHNIST256
from crypto.dh import DH5, DH15
from crypto.symmetric import AES128CBCCipher
from packets import IPSec

class DHFactory():
	@staticmethod
	def get_supported_groups():
		return [0x9, 0x8, 0x7, 0x3, 0x4, 0xa];

	@staticmethod
	def get(group):
		if group == 0x7:
			return ECDHNIST256();
		elif group == 0x8:
			return ECDHNIST384();
		elif group == 0x9:
			return ECDHNIST521();
		elif group == 0xa:
			return ECDHSECP160R1();
		elif group == 0x3:
			return DH5();
		elif group == 0x4:
			return DH15();
		else:
			raise Exception("Not implemented");

class SymmetricCiphersFactory():
	@staticmethod
	def get_supported_ciphers():
		return [0x2];

	@staticmethod
	def get(cipher):
		if cipher == 0x2:
			return AES128CBCCipher();
		else:
			raise Exception("Not implemented");

class HITSuitFactory():
	@staticmethod
	def get_supported_hash_algorithms():
		return [0x10, 0x20];
	
class TransportFactory():
	@staticmethod
	def get_supported_transports():
		return [IPSec.IPSEC_TRANSPORT_FORMAT];