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
sys.path.append("../");

from network.pytun import TunTunnel
from time import sleep

PSEUDO_HEADER_SIZE = 0x4;

class Tun():
	"""
	Initializes the tun device
	"""
	def __init__(self, address = "2001::1", mtu = 1500, name = "hip0"):
		self.name = name;
		self.tun = TunTunnel(pattern = name);
		self.tun.set_ipv6(address);
		self.tun.set_mtu(mtu);
	"""
	Reads data from device
	"""
	def read(self, nbytes = 1500):
		#return self.tun.recv(nbytes + PSEUDO_HEADER_SIZE);
		return self.tun.recv(nbytes);
	"""
	Writes buffer to device
	"""
	def write(self, buf):
		return self.tun.send(buf);
	"""
	Closes TUN interface
	"""
	def close(self):
		self.tun.down();

