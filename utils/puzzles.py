#!/usr/bin/python

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
from os import urandom

from crypto import digest
from math import floor, pow
from packets import HIP

BITS_IN_BYTE = 8;

class PuzzleSolver():
	@staticmethod
	def ltrunc(bitstring, length):
		full_bytes_length = floor(length / BITS_IN_BYTE);
		partial_bits = length % BITS_IN_BYTE;
		full_bytes = bitstring[len(bitstring) - full_bytes_length: len(bitstring)];
		if partial_bits > 0:
			mask = (2 << partial_bits) - 1;
			return bytearray([bitstring[len(bitstring) - full_bytes_length - 1] & mask]) + full_bytes;
		else:
			return full_bytes;
			
	@staticmethod
	def solve_puzzle(irandom, responers_hit, senders_hit, difficulty, rhash):
		if not isinstance(rhash, digest.Digest):
			raise Exception("RHASH must be digest");
		expected_solution = bytearray([0] * floor(difficulty / BITS_IN_BYTE));
		if difficulty % BITS_IN_BYTE > 0:
			expected_solution += bytearray([0]);
		jrandom = bytearray(urandom(len(irandom)));
		while bytearray(PuzzleSolver.ltrunc(rhash.digest(irandom + senders_hit + responers_hit + jrandom), difficulty)) != expected_solution:
			jrandom = bytearray(urandom(len(irandom)));
		return jrandom

	@staticmethod
	def verify_puzzle(irandom, jrandom, responers_hit, senders_hit, difficulty, rhash):
		if not isinstance(rhash, digest.Digest):
			raise Exception("RHASH must be digest");
		expected_solution = bytearray([0] * floor(difficulty / BITS_IN_BYTE));
		if difficulty % BITS_IN_BYTE > 0:
			expected_solution += bytearray([0]);
		return bytearray(PuzzleSolver.ltrunc(rhash.digest(irandom + senders_hit + responers_hit + jrandom), difficulty)) == expected_solution

	@staticmethod
	def generate_irandom(length):
		return urandom(length);