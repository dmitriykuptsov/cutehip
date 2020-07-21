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
sys.path.append(os.getcwd() + "../")
sys.path.append(os.getcwd())

from os import urandom
from time import time

# Crypto
import crypto
# SHA256 HMAC
from crypto.digest import SHA256HMAC
# AES 256 CBC mode
from crypto.symmetric import AES256CBCCipher

import packets
# HIP related packets
from packets import HIP
# IPSec packets
from packets import IPSec
# IPv6 packets
from packets import IPv6
# IPv4 packets 
from packets import IPv4

import utils
from utils.misc import Math


cipher_key = urandom(AES256CBCCipher.KEY_SIZE_BITS);
hmac_key = urandom(SHA256HMAC.LENGTH);
spi = urandom(4);
seq = 1;
for i in range(0, 100):
	
	start = time();
	cipher = AES256CBCCipher();
	hmac = SHA256HMAC(hmac_key);

	iv = urandom(AES256CBCCipher.BLOCK_SIZE);
	data = urandom(1400);

	padded_data = IPSec.IPSecUtils.pad(cipher.BLOCK_SIZE, list(data), 58);
	encrypted_data = cipher.encrypt(cipher_key, iv, bytearray(padded_data));

	ip_sec_packet = IPSec.IPSecPacket();
	ip_sec_packet.set_spi(Math.bytes_to_int(spi));
	ip_sec_packet.set_sequence(seq);
	ip_sec_packet.add_payload(list(iv) + list(encrypted_data));

	icv = hmac.digest(bytearray(ip_sec_packet.get_byte_buffer()));
	ip_sec_packet.add_payload(list(icv));

	# Send ESP packet to destination
	ipv4_packet = IPv4.IPv4Packet();
	ipv4_packet.set_version(IPv4.IPV4_VERSION);
	ipv4_packet.set_destination_address([192, 168, 0, 121]);
	ipv4_packet.set_source_address([192, 168, 0, 101]);
	ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
	ipv4_packet.set_protocol(IPSec.IPSEC_PROTOCOL);
	ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
	ipv4_packet.set_payload(ip_sec_packet.get_byte_buffer());

	seq += 1;

	end = time();

	print(end - start);
	