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


class DIFactory():
	@staticmethod
	def get(type, value):
		if type == DomainID.DI_FQDN:
			return FQDNDomainID(value);
		elif type == DomainID.DI_NAI:
			return NAIDomainID(value);
		return DomainID(); 

class DomainID():
	DI_NONE = 0x0;
	DI_FQDN = 0x1;
	DI_NAI  = 0x2;

	def __init__(self, buffer = None):
		self.buffer = [];
	def to_byte_array(self):
		return self.buffer;
	def get_length(self):
		return 0;
	def get_type(self):
		return self.DI_NONE;

class FQDNDomainID(DomainID):
	def __init__(self, buffer = None):
		if buffer:
			self.buffer = buffer;
	def to_byte_array(self):
		return self.buffer;
	def get_length(self):
		return len(self.buffer);
	def get_type(self):
		return self.DI_FQDN;

class NAIDomainID(DomainID):
	def __init__(self, buffer = None):
		if buffer:
			self.buffer = buffer;
	def to_byte_array(self):
		return self.buffer;
	def get_length(self):
		return len(self.buffer);
	def get_type(self):
		return self.DI_NAI;
	def __str__(self):
		return "Type: " + str(self.get_type()) + ", Value: " + self.to_byte_array().decode("ascii"); 
