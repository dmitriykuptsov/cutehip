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

# https://tools.ietf.org/html/rfc791#section-3.1

IPV4_VERSION_OFFSET             = 0x0;
IPV4_IHL_OFFSET                 = 0x0;
IPV4_TYPE_OF_SERVICE            = 0x1;
IPV4_TOTAL_LENGTH_OFFSET        = 0x2;
IPV4_IDENTIFICATION_OFFSET      = 0x4;
IPV4_FLAGS_OFFSET               = 0x6;
IPV4_FRAGMENT_OFFSET            = 0x6;
IPV4_TTL_OFFSET                 = 0x8;
IPV4_PROTOCOL_OFFSET            = 0x9;
IPV4_CHECKSUM_OFFSET            = 0xA;
IPV4_SOURCE_ADDRESS_OFFSET      = 0xC;
IPV4_DESTINATION_ADDRESS_OFFSET = 0x10;

IPV4_SOURCE_ADDRESS_LENGTH      = 0x4;
IPV4_DESTINATION_ADDRESS_LENGTH = 0x4;

IPV4_MIN_HEADER_LENGTH          = 0x14;

IPV4_DEFAULT_TTL 				= 0x80;
IPV4_VERSION                    = 0x4;
IPV4_IHL_NO_OPTIONS             = 0x5;

class IPv4Packet():
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = [0] * IPV4_MIN_HEADER_LENGTH;
	def get_version(self):
		return (self.buffer[IPV4_VERSION_OFFSET] >> 0x4) & 0xF;
	def set_version(self, version):
		self.buffer[IPV4_VERSION_OFFSET] = self.buffer[IPV4_VERSION_OFFSET] | (version << 0x4);
	def get_ihl(self):
		return (self.buffer[IPV4_IHL_OFFSET] & 0xF);
	def set_ihl(self, ihl):
		self.buffer[IPV4_IHL_OFFSET] = self.buffer[IPV4_IHL_OFFSET] | ihl;
	def get_service_type(self):
		return self.buffer[IPV4_TYPE_OF_SERVICE];
	def set_service_type(self, service_type):
		self.buffer[IPV4_TYPE_OF_SERVICE] = service_type;
	def get_total_length(self):
		return (self.buffer[IPV4_TOTAL_LENGTH_OFFSET] << 0x8) | self.buffer[IPV4_TOTAL_LENGTH_OFFSET + 1];
	def set_total_length(self, total_length):
		self.buffer[IPV4_TOTAL_LENGTH_OFFSET] = (total_length >> 0x8) & 0xFF;
		self.buffer[IPV4_TOTAL_LENGTH_OFFSET + 1] = (total_length & 0xFF);
	def get_identification(self):
		return (self.buffer[IPV4_IDENTIFICATION_OFFSET] << 0x8) | self.buffer[IPV4_IDENTIFICATION_OFFSET + 1];
	def set_identification(self, identification):
		self.buffer[IPV4_IDENTIFICATION_OFFSET] = (identification >> 0x8) & 0xFF;
		self.buffer[IPV4_IDENTIFICATION_OFFSET + 1] = (identification & 0xFF);
	def get_flags(self):
		return (self.buffer[IPV4_FLAGS_OFFSET] >> 0x5);
	def set_flags(self, flags):
		self.buffer[IPV4_FLAGS_OFFSET] = self.buffer[IPV4_FLAGS_OFFSET] | (flags << 0x5);
	def get_fragment_offset(self):
		return ((self.buffer[IPV4_FRAGMENT_OFFSET] << 0x8) & 0x1F) | self.buffer[IPV4_FRAGMENT_OFFSET + 1];
	def set_fragment_offset(self, offset):
		self.buffer[IPV4_FRAGMENT_OFFSET] = self.buffer[IPV4_FRAGMENT_OFFSET] | ((offset >> 0x8) & 0x1F);
		self.buffer[IPV4_FRAGMENT_OFFSET + 1] = (offset & 0xFF);
	def get_ttl(self):
		return self.buffer[IPV4_TTL_OFFSET];
	def set_ttl(self, ttl):
		self.buffer[IPV4_TTL_OFFSET] = ttl;
	def get_protocol(self):
		return self.buffer[IPV4_PROTOCOL_OFFSET];
	def set_protocol(self, protocol):
		self.buffer[IPV4_PROTOCOL_OFFSET] = protocol;
	def get_checksum(self):
		return (self.buffer[IPV4_CHECKSUM_OFFSET] << 0x8) | self.buffer[IPV4_CHECKSUM_OFFSET + 1];
	def set_checksum(self, checksum):
		self.buffer[IPV4_CHECKSUM_OFFSET] = (checksum >> 0x8) & 0xFF;
		self.buffer[IPV4_CHECKSUM_OFFSET + 1] = (checksum & 0xFF);
	def get_source_address(self):
		return self.buffer[IPV4_SOURCE_ADDRESS_OFFSET:IPV4_SOURCE_ADDRESS_OFFSET + IPV4_SOURCE_ADDRESS_LENGTH];
	def set_source_address(self, address):
		self.buffer[IPV4_SOURCE_ADDRESS_OFFSET:IPV4_SOURCE_ADDRESS_OFFSET + IPV4_SOURCE_ADDRESS_LENGTH] = address;
	def get_destination_address(self):
		return self.buffer[IPV4_DESTINATION_ADDRESS_OFFSET:IPV4_DESTINATION_ADDRESS_OFFSET + IPV4_SOURCE_ADDRESS_LENGTH];
	def set_destination_address(self, address):
		self.buffer[IPV4_DESTINATION_ADDRESS_OFFSET:IPV4_DESTINATION_ADDRESS_OFFSET + IPV4_DESTINATION_ADDRESS_LENGTH] = address;
	def set_payload(self, payload):
		self.buffer += payload;
	def get_payload(self):
		offset = self.get_ihl() * 4;
		return self.buffer[offset:];
	def get_buffer(self):
		return self.buffer;