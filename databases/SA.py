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

# Logging
import logging

# Crypto stuff
import crypto
from crypto import factory

import utils
from utils import misc;

class SecurityAssociationRecord():
	def __init__(self, aes_alg, hmac_alg, aes_key, hmac_key, src, dst):
		self.sequnce  = 1;
		self.spi      = None;
		self.aes_key  = aes_key;
		self.hmac_key = hmac_key;
		self.aes_alg  = factory.SymmetricCiphersFactory.get(aes_alg);
		self.hmac_alg = factory.HMACFactory.get(hmac_alg, self.hmac_key);
		self.src      = src;
		self.dst      = dst;

	def get_spi(self):
		return self.spi;
	def set_spi(self, spi):
		self.spi = spi;
	def get_sequence(self):
		return self.sequnce;
	def increment_sequence(self):
		self.sequnce += 1;
	def get_hmac_alg(self):
		return self.hmac_alg;
	def get_aes_alg(self):
		return self.aes_alg;
	def get_aes_key(self):
		return self.aes_key;
	def get_hmac_key(self):
		return self.hmac_key;
	def get_src(self):
		return self.src;
	def get_dst(self):
		return self.dst;

class SecurityAssociationDatabase():
	def __init__(self):
		self.db = dict();
	def key(self, source, destination):
		return hash(source + destination);
	def add_record(self, source, destination, record):
		logging.debug("Adding record for %s - %s" % (source, destination));
		self.db[self.key(source, destination)] = record;
	def get_record(self, source, destination):
		return self.db[self.key(source, destination)];
	def delete_record(self):
		del self.db[self.key(source, destination)];