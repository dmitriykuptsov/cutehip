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

# https://tools.ietf.org/html/rfc7402
# https://tools.ietf.org/html/rfc4303

IPSEC_TRANSPORT_FORMAT      = 0x0FFF;

IPSEC_PROTOCOL              = 0x32;

IPSEC_SPI_LENGTH            = 0x4;
IPSEC_SEQUENCE_LENGTH       = 0x4;

IPSEC_SPI_OFFSET            = 0x0;
IPSEC_SEQUENCE_OFFSET       = 0x4;
IPSEC_PAYLOAD_OFFSET        = 0x8;

class IPSecPacket():
	def __init__(self, buffer = None):
		if not buffer:
			self.buffer = [0] * (IPSEC_SPI_LENGTH + IPSEC_SEQUENCE_LENGTH)
		else:
			self.buffer = buffer
	def add_payload(self, payload):
		self.buffer += payload;
	def get_payload(self, iv_length):
		payload_length = (len(self.buffer) - 
			IPSEC_SPI_LENGTH - 
			IPSEC_SEQUENCE_LENGTH - 
			iv_length);
		return self.buffer[IPSEC_PAYLOAD_OFFSET:IPSEC_PAYLOAD_OFFSET + payload_length];
	def set_spi(self, spi):
		self.buffer[IPSEC_SPI_OFFSET] = (spi >> 24) & 0xFF;
		self.buffer[IPSEC_SPI_OFFSET + 1] = (spi >> 16) & 0xFF;
		self.buffer[IPSEC_SPI_OFFSET + 2] = (spi >> 8) & 0xFF;
		self.buffer[IPSEC_SPI_OFFSET + 3] = (spi & 0xFF);
	def get_spi(self):
		return ((self.buffer[IPSEC_SPI_OFFSET] << 24) |
			(self.buffer[IPSEC_SPI_OFFSET + 1] << 16) |
			(self.buffer[IPSEC_SPI_OFFSET + 2] << 8)  |
			self.buffer[IPSEC_SPI_OFFSET + 3]);
	def set_sequence(self, sequence):
		self.buffer[IPSEC_SEQUENCE_OFFSET] = (sequence >> 24) & 0xFF;
		self.buffer[IPSEC_SEQUENCE_OFFSET + 1] = (sequence >> 16) & 0xFF;
		self.buffer[IPSEC_SEQUENCE_OFFSET + 2] = (sequence >> 8) & 0xFF;
		self.buffer[IPSEC_SEQUENCE_OFFSET + 3] = (sequence & 0xFF);
	def get_sequence(self):
		return ((self.buffer[IPSEC_SEQUENCE_OFFSET] << 24) |
			(self.buffer[IPSEC_SEQUENCE_OFFSET + 1] << 16) |
			(self.buffer[IPSEC_SEQUENCE_OFFSET + 2] << 8)  |
			self.buffer[IPSEC_SEQUENCE_OFFSET + 3]);

