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

import logging

class Resolver():
	def __init__(self):
		pass

	def resolve(self, hit):
		pass

class HostsFileResolver(Resolver):
	def __init__(self, filename=None):
		fh = open(filename);
		self.mapping = dict();
		lines = fh.readlines();
		logging.info("Importing hosts file");
		for record in lines:
			record = record.split(" ");
			if len(record) != 2:
				continue;
			self.mapping[record[0].rstrip()] = record[1];
			logging.info("%s %s", record[0].rstrip(), record[1]);
	def resolve(self, hit):
		return self.mapping.get(hit, None);
