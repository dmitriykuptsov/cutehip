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

from os import system
import re
import netifaces

class Routing():
	"""
	Routing configuration
	"""
	@staticmethod
	def add_hip_default_route(interface = "hip0", prefix="2001:0010::/28"):
		"""
		Adds default route for IPv6 packets
		"""
		system("ip -6 route add %s dev %s" % (prefix, interface));
	@staticmethod
	def del_hip_default_route(interface = "hip0", prefix="2001:0010::/28"):
		"""
		Removes default route for IPv6 packets
		"""
		system("ip -6 route del %s dev %s" % (prefix, interface));

	@staticmethod
	def get_IPv4_default_route_interface():
		"""
		Gets interface name of a default route
		"""
		gws=netifaces.gateways()
		try:
			index = list(gws["default"].keys())[0];
			return gws["default"][index][1]
		except:
			return None
	@staticmethod
	def get_default_IPv4_address():
		"""
		Gets default IPv4 address
		"""
		interface = Routing.get_IPv4_default_route_interface();
		addresses = netifaces.ifaddresses(interface);
		for k in list(addresses.keys()):
			if re.match("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", addresses[k][0]["addr"]):
				return addresses[k][0]["addr"]
		return None;

