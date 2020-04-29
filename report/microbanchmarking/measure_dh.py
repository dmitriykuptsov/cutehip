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

from dh import DH5, DH14, DH15, DH16, DH17, DH18

for i in range(0, 100):
	start = time();
	_dh1 = DH5();
	_dh2 = DH5();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	assert _dh1.compute_shared_secret(pub2) == _dh2.compute_shared_secret(pub1)
	end = time();
	print("5, " + str(end - start))

for i in range(0, 100):
	start = time();
	_dh1 = DH14();
	_dh2 = DH14();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	assert _dh1.compute_shared_secret(pub2) == _dh2.compute_shared_secret(pub1)
	end = time();
	print("14, " + str(end - start))

for i in range(0, 100):
	start = time();
	_dh1 = DH15();
	_dh2 = DH15();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	assert _dh1.compute_shared_secret(pub2) == _dh2.compute_shared_secret(pub1)
	end = time();
	print("15, " + str(end - start))

for i in range(0, 100):
	start = time();
	_dh1 = DH16();
	_dh2 = DH16();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	assert _dh1.compute_shared_secret(pub2) == _dh2.compute_shared_secret(pub1)
	end = time();
	print("16, " + str(end - start))

for i in range(0, 100):
	start = time();
	_dh1 = DH17();
	_dh2 = DH17();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	assert _dh1.compute_shared_secret(pub2) == _dh2.compute_shared_secret(pub1)
	end = time();
	print("17, " + str(end - start))

for i in range(0, 100):
	start = time();
	_dh1 = DH18();
	_dh2 = DH18();
	_dh1.generate_private_key();
	_dh2.generate_private_key();
	pub1 = _dh1.generate_public_key();
	pub2 = _dh2.generate_public_key();
	assert _dh1.compute_shared_secret(pub2) == _dh2.compute_shared_secret(pub1)
	end = time();
	print("18, " + str(end - start))
