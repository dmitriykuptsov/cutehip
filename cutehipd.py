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

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2020, stangebit"
__license__ = "GPL"
__version__ = "0.0.1a"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@gmail.com"
__status__ = "development"

# Import the needed libraries
# Sockets
import socket
# Threading
import threading
# Logging
import logging
# Timing
import time
# System
import sys
# Exit handler
import atexit
# HIP related packets
from packets import HIP
# IPSec packets
from packets import IPSec
# IPv6 packets
from packets import IPv6
# IPv4 packets 
from packets import IPv4
# Configuration
from config import config
# HIT
from utils.hit import HIT
from utils.hi import RSAHostID
from utils.di import DIFactory
# Utilities
from utils.misc import Utils, Math
# Puzzle solver
from utils.puzzles import PuzzleSolver
# Crypto
from crypto import factory
from crypto.asymmetric import RSAPublicKey
# Tun interface
from network import tun
# Routing
from network import routing
# States
from databases import HIPState
from databases import SA
from databases import resolver
# Utilities
from utils import misc
# Configure logging to console
#logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
logging.basicConfig(
	level=logging.DEBUG,
	format="%(asctime)s [%(levelname)s] %(message)s",
	handlers=[
		logging.FileHandler("hip.log"),
		logging.StreamHandler(sys.stdout)
	]
);

MTU = config.config["network"]["mtu"];

# HIP v2 https://tools.ietf.org/html/rfc7401#section-3
logging.info("Using hosts file to resolve HITS %s" % (config.config["resolver"]["hosts_file"]));
hit_resolver = resolver.HostsFileResolver(filename = config.config["resolver"]["hosts_file"]);
hip_state_machine = HIPState.StateMachine();
ip_sec_sa = SA.SecurityAssociationDatabase();

logging.info("Initializing HIP socket");
hip_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, HIP.HIP_PROTOCOL);
hip_socket.bind(("0.0.0.0", HIP.HIP_PROTOCOL));
# We will need to perform manual fragmentation
hip_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

logging.info("Initializing IPSec socket");
ip_sec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPSec.IPSEC_PROTOCOL);
ip_sec_socket.bind(("0.0.0.0", IPSec.IPSEC_PROTOCOL));
ip_sec_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

di = DIFactory.get(config.config["resolver"]["domain_identifier"]["type"], 
	bytearray(config.config["resolver"]["domain_identifier"]["value"], encoding="ascii"));

logging.info("Loading public key and constructing HIT")
pubkey = RSAPublicKey.load_pem(config.config["security"]["public_key"]);
rsa_hi = RSAHostID(pubkey.get_public_exponent(), pubkey.get_modulus());
ipv6_address = HIT.get_hex_formated(rsa_hi.to_byte_array(), HIT.SHA256_OGA);
own_hit = HIT.get(rsa_hi.to_byte_array(), HIT.SHA256_OGA);
logging.info("Configuring TUN device");
hip_tun = tun.Tun(address=ipv6_address, mtu=MTU);
logging.info("Configuring IPv6 routes");
routing.Routing.add_hip_default_route();

def hip_loop():
	"""
	This loop is responsible for reading HIP packets
	from the raw socket
	"""
	logging.info("Starting the HIP loop");

	while True:
		buf = bytearray(hip_socket.recv(MTU));
		ipv4_packet = IPv4.IPv4Packet(buf);

		src = ipv4_packet.get_source_address();
		dst = ipv4_packet.get_destination_address();

		if ipv4_packet.get_protocol() != HIP.HIP_PROTOCOL:
			logging.debug("Invalid protocol type");
			continue;

		if len(ipv4_packet.get_payload()) % 8:
			logging.debug("Invalid length of the payload. Must be multiple of 8 bytes");
			continue;

		hip_packet = HIP.HIPPacket(ipv4_packet.get_payload());

		shit = hip_packet.get_senders_hit();
		rhit = hip_packet.get_receivers_hit();

		logging.info("Got HIP packet");
		logging.info("Responder's HIT %s" % Utils.ipv6_bytes_to_hex_formatted(rhit));
		logging.info("Our own HIT %s " % Utils.ipv6_bytes_to_hex_formatted(own_hit));

		if hip_packet.get_version() != HIP.HIP_VERSION:
			logging.critical("Only HIP version 2 is supported");
			continue;

		# Check wether the destination address is our own HIT
		if not Utils.hits_equal(rhit, own_hit):
			logging.critical("Not our HIT");
			continue;

		# https://tools.ietf.org/html/rfc7401#section-5
		original_checksum = hip_packet.get_checksum();
		hip_packet.set_checksum(0x0);
		# Verify checksum
		checksum = misc.Utils.hip_ipv4_checksum(
			src, 
			dst, 
			HIP.HIP_PROTOCOL, 
			hip_packet.get_length() * 8 + 8, 
			hip_packet.get_buffer());
		if original_checksum != checksum:
			logging.critical("Invalid checksum");
			continue;

		if hip_packet.get_packet_type() == HIP.HIP_I1_PACKET:
			logging.info("I1 packet");
			
			# Check the state of the HIP protocol
			# R1 packet should be constructed only 
			# if the state is not associated
			# Need to check with the RFC

			# Construct R1 packet
			hip_r1_packet = HIP.R1Packet();
			hip_r1_packet.set_senders_hit(rhit);
			hip_r1_packet.set_receivers_hit(shit);
			hip_r1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
			hip_r1_packet.set_version(HIP.HIP_VERSION);

			r_hash = HIT.get_responders_hash_algorithm(rhit);

			# Prepare puzzle
			irandom = PuzzleSolver.generate_irandom(r_hash.LENGTH);
			puzzle_param = HIP.PuzzleParameter(buffer = None, rhash_length = rhash.LENGTH);
			puzzle_param.set_k_value(config.config["security"]["puzzle_difficulty"]);
			puzzle_param.set_lifetime(config.config["security"]["puzzle_lifetime_exponent"]);
			
			# HIP DH groups parameter
			dh_groups_param = HIP.DHGroupListParameter();
			# Prepare Diffie-Hellman parameters
			dh_groups_param_initiator = None;
			parameters = hip_packet.get_parameters();
			for parameter in parameters:
				if isinstance(parameter, HIP.DHGroupListParameter):
					dh_groups_param_initiator = parameter;
			if not dh_groups_param_initiator:
				# Drop HIP BEX?
				logging.debug("No DH groups parameter found");
				continue;
			offered_dh_groups = dh_groups_param_initiator.get_groups();
			supported_dh_groups = factory.DHFactory.get_supported_groups();
			selected_dh_group = None;
			for group in supported_dh_groups:
				if group in offered_dh_groups:
					dh_groups_param.add_groups([group]);
					selected_dh_group = group;
					break;
			if not selected_dh_group:
				logging.debug("Unsupported DH group");
				continue;

			dh = factory.DHFactory.get(selected_dh_group);
			dh.generate_private_key();
			public_key = dh.generate_public_key();
			dh_param = HIP.DHParameter();
			dh_param.set_group_id(selected_dh_group);
			#dh_param.add_public_value(public_key);

			# HIP cipher param
			cipher_param = HIP.CipherParameter();
			cipher_param.add_ciphers(factory.SymmetricCiphersFactory.get_supported_ciphers());

			# HIP host ID parameter
			hi_param = HIP.HostIdParameter();
			hi_param.set_host_id(rsa_hi);
			# It is important to set domain ID after host ID was set
			hi_param.set_domain_id(di);

			# HIP HIT suit list parameter
			hit_suit_param = HIP.HITSuitListParameter();
			hit_suit_param.add_suits(factory.HITSuitFactory.get_supported_hash_algorithms());

			# Transport format list
			transport_param = HIP.TransportListParameter();
			transport_param.add_transport_formats([IPSec.IPSEC_TRANSPORT_FORMAT]);

			# HIP signature parameter
			signature_param = HIP.Signature2Parameter();
			#

			# Compute signature here

			# Add parameters to R1 packet (order is important)
			# List of mandatory parameters in R1 packet...
			puzzle_param.set_random(irandom);
			hip_r1_packet.add_parameter(puzzle_param);
			#hip_r1_packet.add_parameter(dh_param);
			hip_r1_packet.add_parameter(cipher_param);
			hip_r1_packet.add_parameter(hi_param);
			hip_r1_packet.add_parameter(hit_suit_param);
			hip_r1_packet.add_parameter(dh_groups_param);
			hip_r1_packet.add_parameter(transport_param);
			#hip_r1_packet.add_parameter(signature_param);

			# Swap the addresses
			temp = src;
			src = dst;
			dst = temp;

			# Create IPv4 packet
			ipv4_packet = IPv4.IPv4Packet();
			ipv4_packet.set_version(IPv4.IPV4_VERSION);
			ipv4_packet.set_destination_address(dst);
			ipv4_packet.set_source_address(src);
			ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
			ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
			ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

			# Calculate the checksum
			checksum = misc.Utils.hip_ipv4_checksum(
				src, 
				dst, 
				HIP.HIP_PROTOCOL, 
				hip_r1_packet.get_length() * 8 + 8, 
				hip_r1_packet.get_buffer());
			hip_r1_packet.set_checksum(checksum);
			ipv4_packet.set_payload(hip_r1_packet.get_buffer());
			# Send the packet
			dst_str = Utils.ipv4_bytes_to_string(dst);
			logging.debug("Sending R1 packet to %s " % dst_str);
			hip_socket.sendto(
				bytearray(ipv4_packet.get_buffer()), 
				(dst_str, 0));
		elif hip_packet.get_packet_type() == HIP.HIP_R1_PACKET:
			logging.info("R1 packet");
			parameters = hip_packet.get_parameters();
			for parameter in parameters:
				if isinstance(parameter, HIP.DHGroupListParameter):
					logging.debug("DH groups parameter");
				if isinstance(parameter, HIP.R1CounterParameter):
					logging.debug("R1 counter");
				if isinstance(parameter, HIP.PuzzleParameter):
					logging.debug("Puzzle parameter");
					#PuzzleSolver.
				if isinstance(parameter, HIP.DHParameter):
					logging.debug("DH parameter");
				if isinstance(parameter, HIP.HostIdParameter):
					logging.debug("Host ID");
				if isinstance(parameter, HIP.HITSuitListParameter):
					logging.debug("HIT suit list");
				if isinstance(parameter, HIP.TransportListParameter):
					logging.debug("Transport parameter");
					logging.debug(parameter.get_transport_formats());
				if isinstance(parameter, HIP.Signature2Parameter):
					logging.debug("Signature parameter");
				if isinstance(parameter, HIP.CipherParameter):
					logging.debug("Ciphers");
		elif hip_packet.get_packet_type() == HIP.HIP_I2_PACKET:
			logging.info("I2 packet");
		elif hip_packet.get_packet_type() == HIP.HIP_R2_PACKET:
			logging.info("R2 packet");
		elif hip_packet.get_packet_type() == HIP.HIP_UPDATE_PACKET:
			logging.info("UPDATE packet");
		elif hip_packet.get_packet_type() == HIP.HIP_NOTIFY_PACKET:
			logging.info("NOTIFY packet");
		elif hip_packet.get_packet_type() == HIP.HIP_CLOSE_PACKET:
			logging.info("CLOSE packet");
		elif hip_packet.get_packet_type == HIP.HIP_CLOSE_ACK_PACKET:
			logging.info("CLOSE ACK packet");

def ip_sec_loop():
	"""
	This loop is responsible for reading IPSec packets
	from the raw socket
	"""
	logging.info("Starting the IPSec loop");

	while True:
		buf = bytearray(ip_sec_socket.recv(MTU));
		ipv4_packet = IPv4.IPv4Packet(buf);

def tun_if_loop():
	"""
	This loop is responsible for reading the packets 
	from the TUN interface
	"""
	logging.info("Starting the TUN interface loop");
	while True:
		buf = hip_tun.read(MTU);
		logging.info("Got packet on TUN interface %s bytes" % (len(buf)));
		packet = IPv6.IPv6Packet(buf);
		shit = packet.get_source_address();
		rhit = packet.get_destination_address();
		logging.info("Source %s " % Utils.ipv6_bytes_to_hex_formatted(shit));
		logging.info("Destination %s " % Utils.ipv6_bytes_to_hex_formatted(rhit));
		logging.info("Version %s " % (packet.get_version()));
		logging.info("Traffic class %s " % (packet.get_traffic_class()));
		logging.info("Flow label %s " % (packet.get_flow_label()));
		logging.info("Packet length %s " %(packet.get_payload_length()));
		logging.info("Next header %s " % (packet.get_next_header()));
		logging.info("Hop limit %s" % (packet.get_hop_limit()));
		# Get the state
		hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(shit), 
			Utils.ipv6_bytes_to_hex_formatted(rhit));
		if hip_state.is_unassociated():
			logging.debug("Unassociate state reached");
			logging.info("Resolving %s to IPv4 address" % Utils.ipv6_bytes_to_hex_formatted(rhit));

			# Resolve the HIT code can be improved
			if not hit_resolver.resolve(Utils.ipv6_bytes_to_hex_formatted(rhit)):
				logging.critical("Cannot resolve HIT to IPv4 address");
				continue;

			# Convert bytes to string representation of IPv6 address
			dst_str = hit_resolver.resolve(
				Utils.ipv6_bytes_to_hex_formatted(rhit));
			dst = misc.Math.int_to_bytes(
				misc.Utils.ipv4_to_int(dst_str));
			src = misc.Math.int_to_bytes(
				misc.Utils.ipv4_to_int(
					routing.Routing.get_default_IPv4_address()));

			# Construct the DH groups parameter
			dh_groups_param = HIP.DHGroupListParameter();
			dh_groups_param.add_groups(factory.DHFactory.get_supported_groups());

			# Create I1 packet
			hip_i1_packet = HIP.I1Packet();
			hip_i1_packet.set_senders_hit(shit);
			hip_i1_packet.set_receivers_hit(rhit);
			hip_i1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
			hip_i1_packet.set_version(HIP.HIP_VERSION);
			hip_i1_packet.add_parameter(dh_groups_param);

			# Compute the checksum of HIP packet
			checksum = misc.Utils.hip_ipv4_checksum(
				src, 
				dst, 
				HIP.HIP_PROTOCOL, 
				hip_i1_packet.get_length() * 8 + 8, 
				hip_i1_packet.get_buffer());
			hip_i1_packet.set_checksum(checksum);

			# Construct the IPv4 packet
			ipv4_packet = IPv4.IPv4Packet();
			ipv4_packet.set_version(IPv4.IPV4_VERSION);
			ipv4_packet.set_destination_address(dst);
			ipv4_packet.set_source_address(src);
			ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
			ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
			ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
			ipv4_packet.set_payload(hip_i1_packet.get_buffer());

			# Send HIP I1 packet to destination
			hip_socket.sendto(bytearray(ipv4_packet.get_buffer()), (dst_str, 0));

			# Transition to an I1-Sent state
			hip_state.i1_sent();

		elif hip_state.is_established():
			# Send ESP packet to destination
			pass


hip_th_loop = threading.Thread(target = hip_loop, args = (), daemon = True);
ip_sec_th_loop = threading.Thread(target = ip_sec_loop, args = (), daemon = True);
tun_if_th_loop = threading.Thread(target = tun_if_loop, args = (), daemon = True);

logging.info("Starting the CuteHIP");

hip_th_loop.start();
ip_sec_th_loop.start();
tun_if_th_loop.start();

main_loop = True;

while main_loop:
	#print("Periodic tasks")
	time.sleep(1);

def exit_handler():
	routing.Routing.del_hip_default_route();
	main_loop = False;

atexit.register(exit_handler);
