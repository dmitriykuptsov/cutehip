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

IPV6_VERSION_OFFSET                      = 0x0;
IPV6_TRAFFIC_CLASS_OFFSET                = 0x0;
IPV6_FLOW_LABEL_OFFSET                   = 0x1;
IPV6_PAYLOAD_LENGTH_OFFSET               = 0x4;
IPV6_NEXT_HEADER_OFFSET                  = 0x6;
IPV6_HOP_LIMIT_OFFSET                    = 0x7;
IPV6_SOURCE_ADDRESS_OFFSET               = 0x8;
IPV6_DESTINATION_ADDRESS_OFFSET          = 0x18;

IPV6_VER_TRAFFIC_CLASS_FLOW_LABEL_LENGTH = 0x4;
IPV6_PAYLOAD_LENGTH_LENGTH               = 0x2;
IPV6_NEXT_HEADER_LENGTH                  = 0x1;
IPV6_HOP_LIMIT_LENGTH                    = 0x1;

IPV6_SOURCE_ADDRESS_LENGTH               = 0x10;
IPV6_DESTINATION_ADDRESS_LENGTH          = 0x10;

IPV6_HEADER_LENGTH                       = 0x28;

IPV6_PROTOCOL                            = 0x29;
IPV6_VERSION                             = 0x6;

class IPv6Packet():
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = [0] * IPV6_HEADER_LENGTH;
	def get_version(self):
		return (self.buffer[IPV6_VERSION_OFFSET] >> 0x4);
	def set_version(self, version):
		self.buffer[IPV6_VERSION_OFFSET] = (version << 0x4) | self.buffer[IPV6_VERSION_OFFSET];
	def get_traffic_class(self):
		return ((self.buffer[IPV6_TRAFFIC_CLASS_OFFSET] & 0xF) << 4) | (self.buffer[IPV6_TRAFFIC_CLASS_OFFSET + 1] >> 0x4);
	def set_traffic_class(self, traffic_class):
		self.buffer[IPV6_TRAFFIC_CLASS_OFFSET] = 0xF0
		self.buffer[IPV6_TRAFFIC_CLASS_OFFSET] = self.buffer[IPV6_TRAFFIC_CLASS_OFFSET] | (traffic_class >> 0x4);
		self.buffer[IPV6_TRAFFIC_CLASS_OFFSET + 1] = self.buffer[IPV6_TRAFFIC_CLASS_OFFSET + 1] | ((traffic_class << 0x4) & 0xF0);
	def get_flow_label(self):
		return ((self.buffer[IPV6_FLOW_LABEL_OFFSET] & 0xF) << 16 |
				self.buffer[IPV6_FLOW_LABEL_OFFSET + 1] << 8 |
				self.buffer[IPV6_FLOW_LABEL_OFFSET + 2]);
	def set_flow_label(self, flow_label):
		self.buffer[IPV6_FLOW_LABEL_OFFSET] = (self.buffer[IPV6_FLOW_LABEL_OFFSET] | ((flow_label >> 16) & 0xF));
		self.buffer[IPV6_FLOW_LABEL_OFFSET + 1] = ((flow_label >> 8) & 0xFF);
		self.buffer[IPV6_FLOW_LABEL_OFFSET + 2] = (flow_label & 0xFF);
	def get_payload_length(self):
		return (self.buffer[IPV6_PAYLOAD_LENGTH_OFFSET] << 8) | self.buffer[IPV6_PAYLOAD_LENGTH_OFFSET + 1];
	def set_payload_length(self, payload_length):
		self.buffer[IPV6_PAYLOAD_LENGTH_OFFSET] = ((payload_length >> 8) & 0xFF);
		self.buffer[IPV6_PAYLOAD_LENGTH_OFFSET + 1] = (payload_length & 0xFF);
	def get_next_header(self):
		return self.buffer[IPV6_NEXT_HEADER_OFFSET];
	def set_next_header(self, next_header):
		self.buffer[IPV6_NEXT_HEADER_OFFSET] = next_header;
	def get_hop_limit(self):
		return self.buffer[IPV6_HOP_LIMIT_OFFSET];
	def set_hop_limit(self, hop_limit):
		self.buffer[IPV6_HOP_LIMIT_OFFSET] = (hop_limit & 0xFF);
	def get_source_address(self):
		return (self.buffer[IPV6_SOURCE_ADDRESS_OFFSET:IPV6_SOURCE_ADDRESS_OFFSET + IPV6_SOURCE_ADDRESS_LENGTH]);
	def set_source_address(self, source_address):
		self.buffer[IPV6_SOURCE_ADDRESS_OFFSET:IPV6_SOURCE_ADDRESS_OFFSET + IPV6_SOURCE_ADDRESS_LENGTH] = source_address;
	def get_destination_address(self):
		return (self.buffer[IPV6_DESTINATION_ADDRESS_OFFSET:IPV6_DESTINATION_ADDRESS_OFFSET + IPV6_SOURCE_ADDRESS_LENGTH]);
	def set_destination_address(self, destination_address):
		self.buffer[IPV6_DESTINATION_ADDRESS_OFFSET:IPV6_DESTINATION_ADDRESS_OFFSET + IPV6_DESTINATION_ADDRESS_LENGTH] = destination_address;
	def get_payload(self):
		return self.buffer[IPV6_HEADER_LENGTH:]
	def set_payload(self, buffer):
		self.buffer[IPV6_HEADER_LENGTH:] = buffer;
	def get_buffer(self):
		return self.buffer;