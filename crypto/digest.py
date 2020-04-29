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

from Crypto.Hash import HMAC, SHA256, SHA224, SHA384, SHA1

class HMACDigest():
	def __init__(self, key):
		self.key = key;
	def digest(data):
		raise Exception("Not implemented");

class SHA256HMAC(HMACDigest):
	def __init__(self, key):
		self.key = key;
	def digest(self, data):
		self.hmac = HMAC.new(self.key, digestmod=SHA256)
		self.hmac.update(data);
		return self.hmac.digest();

class SHA224HMAC(HMACDigest):
	def __init__(self, key):
		self.key = key;
	def digest(self, data):
		self.hmac = HMAC.new(self.key, digestmod=SHA224)
		self.hmac.update(data);
		return self.hmac.digest();

class SHA384HMAC(HMACDigest):
	def __init__(self, key):
		self.key = key;
	def digest(self, data):
		self.hmac = HMAC.new(self.key, digestmod=SHA384)
		self.hmac.update(data);
		return self.hmac.digest();

class SHA1HMAC(HMACDigest):
	def __init__(self, key):
		self.key = key;
	def digest(self, data):
		self.hmac = HMAC.new(self.key, digestmod=SHA1)
		self.hmac.update(data);
		return self.hmac.digest();

class Digest():
	def __init__(self):
		pass
	def digest(self, data):
		raise Exception("Not implemented");

class SHA256Digest(Digest):
	def __init__(self):
		pass
	def digest(self, data):
		self.sha256 = SHA256.new();
		self.sha256.update(data);
		return self.sha256.digest();

class SHA224Digest(Digest):
	def __init__(self):
		pass
	def digest(self, data):
		self.sha224 = SHA224.new();
		self.sha224.update(data);
		return self.sha256.digest();

class SHA384Digest(Digest):
	def __init__(self):
		pass
	def digest(self, data):
		self.sha384 = SHA384.new();
		self.sha384.update(data);
		return self.sha384.digest();

class SHA1Digest(Digest):
	def __init__(self):
		pass
	def digest(self, data):
		self.sha1 = SHA1.new();
		self.sha1.update(data);
		return self.sha1.digest();


