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

from time import time

# Add upper directory to path
import sys
import os
sys.path.append(os.getcwd() + "/../../utils/")
sys.path.append(os.getcwd() + "/../../crypto/")

from ecdh import ECDHBrainpool256, ECDHSecp256r1, ECDHSecp384r1, ECDHSecp521r1

for i in range(0, 100):
	start = time();
	_dh1 = ECDHSecp256r1();
	_dh2 = ECDHSecp256r1();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	sec1 = _dh1.compute_shared_secret(pub2)
	sec2 = _dh2.compute_shared_secret(pub1)
	assert sec1.x == sec2.x
	assert sec1.y == sec2.y
	end = time();
	print("19, " + str(end - start))

for i in range(0, 100):
	start = time();
	_dh1 = ECDHSecp384r1();
	_dh2 = ECDHSecp384r1();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	sec1 = _dh1.compute_shared_secret(pub2)
	sec2 = _dh2.compute_shared_secret(pub1)
	assert sec1.x == sec2.x
	assert sec1.y == sec2.y
	end = time();
	print("20, " + str(end - start))

for i in range(0, 100):
	start = time();
	_dh1 = ECDHSecp521r1();
	_dh2 = ECDHSecp521r1();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	sec1 = _dh1.compute_shared_secret(pub2)
	sec2 = _dh2.compute_shared_secret(pub1)
	assert sec1.x == sec2.x
	assert sec1.y == sec2.y
	end = time();
	print("21, " + str(end - start))
