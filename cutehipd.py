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
__copyright__ = "Copyright 2020, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@gmail.com"
__status__ = "development"

# Import the needed libraries
# Stacktrace
import traceback
# Sockets
import socket
# Threading
import threading
# Logging
import logging
# Timing
import time
# Math functions
from math import ceil, floor
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
import utils
from utils.hit import HIT
from utils.hi import RSAHostID, ECDSAHostID, ECDSALowHostID
from utils.di import DIFactory
# Utilities
from utils.misc import Utils, Math
# Puzzle solver
from utils.puzzles import PuzzleSolver
# Crypto
from crypto import factory
from crypto.asymmetric import RSAPublicKey, RSAPrivateKey, ECDSAPublicKey, ECDSAPrivateKey, RSASHA256Signature, ECDSALowPublicKey, ECDSALowPrivateKey, ECDSASHA384Signature, ECDSASHA1Signature
from crypto.factory import HMACFactory, SymmetricCiphersFactory, ESPTransformFactory
# Tun interface
from network import tun
# Routing
from network import routing
# States
from databases import HIPState
from databases import SA
from databases import resolver
from databases import Firewall
# Utilities
from utils.misc import Utils
# Configure logging to console and file
logging.basicConfig(
	level=logging.DEBUG,
	format="%(asctime)s [%(levelname)s] %(message)s",
	handlers=[
		logging.FileHandler("hip.log"),
		logging.StreamHandler(sys.stdout)
	]
);

# TUN interface MTU
MTU = config.config["network"]["mtu"];

firewall = Firewall.BasicFirewall();
firewall.load_rules(config.config["firewall"]["rules_file"])

# HIP v2 https://tools.ietf.org/html/rfc7401#section-3
# Configure resolver
logging.info("Using hosts file to resolve HITS %s" % (config.config["resolver"]["hosts_file"]));
hit_resolver = resolver.HostsFileResolver(filename = config.config["resolver"]["hosts_file"]);

# Security association database
ip_sec_sa = SA.SecurityAssociationDatabase();

# Configure the sockets
logging.info("Initializing HIP socket");
hip_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, HIP.HIP_PROTOCOL);
hip_socket.bind(("0.0.0.0", HIP.HIP_PROTOCOL));
# We will need to perform manual fragmentation
hip_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
logging.info("Initializing IPSec socket");
ip_sec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPSec.IPSEC_PROTOCOL);
ip_sec_socket.bind(("0.0.0.0", IPSec.IPSEC_PROTOCOL));
# We will need to perform manual fragmentation
ip_sec_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
# Domain identifier
di = DIFactory.get(config.config["resolver"]["domain_identifier"]["type"], 
	bytearray(config.config["resolver"]["domain_identifier"]["value"], encoding="ascii"));

#logging.debug(di);
logging.info("Loading public key and constructing HIT")
pubkey       = None;
privkey      = None;
hi           = None;
ipv6_address = None;
own_hit      = None;
responder_hi_param = None;
if config.config["security"]["sig_alg"] == 0x5: # RSA
	if config.config["security"]["hash_alg"] != 0x1: # SHA 256
		raise Exception("Invalid hash algorithm. Must be 0x1")
	pubkey = RSAPublicKey.load_pem(config.config["security"]["public_key"]);
	privkey = RSAPrivateKey.load_pem(config.config["security"]["private_key"]);
	hi = RSAHostID(pubkey.get_public_exponent(), pubkey.get_modulus());
	ipv6_address = HIT.get_hex_formated(hi.to_byte_array(), HIT.SHA256_OGA);
	own_hit = HIT.get(hi.to_byte_array(), HIT.SHA256_OGA);
elif config.config["security"]["sig_alg"] == 0x7: # ECDSA
	if config.config["security"]["hash_alg"] != 0x2: # SHA 384
		raise Exception("Invalid hash algorithm. Must be 0x2")
	pubkey = ECDSAPublicKey.load_pem(config.config["security"]["public_key"]);
	privkey = ECDSAPrivateKey.load_pem(config.config["security"]["private_key"]);
	logging.debug(pubkey.get_key_info());
	hi = ECDSAHostID(pubkey.get_curve_id(), pubkey.get_x(), pubkey.get_y());
	ipv6_address = HIT.get_hex_formated(hi.to_byte_array(), HIT.SHA384_OGA);
	logging.debug(list(hi.to_byte_array()));
	self.own_hit = HIT.get(hi.to_byte_array(), HIT.SHA384_OGA);
	logging.debug("Responder's OGA ID %d" % (HIT.SHA384_OGA));
	logging.debug(list(hi.to_byte_array()));
	logging.debug(list(self.own_hit))
elif config.config["security"]["sig_alg"] == 0x9: # ECDSA LOW
	if config.config["security"]["hash_alg"] != 0x3: # SHA 1
		raise Exception("Invalid hash algorithm. Must be 0x3")
	pubkey = ECDSALowPublicKey.load_pem(config.config["security"]["public_key"]);
	privkey = ECDSALowPrivateKey.load_pem(config.config["security"]["private_key"]);
	hi = ECDSALowHostID(pubkey.get_curve_id(), pubkey.get_x(), pubkey.get_y());
	ipv6_address = HIT.get_hex_formated(hi.to_byte_array(), HIT.SHA1_OGA);
	own_hit = HIT.get(hi.to_byte_array(), HIT.SHA1_OGA);
else:
	raise Exception("Unsupported Host ID algorithm")

logging.debug("Configuring TUN interface");
# Configure TUN interface
logging.info("Configuring TUN device");
hip_tun = tun.Tun(address=ipv6_address, mtu=MTU);
logging.info("Configuring IPv6 routes");
# Configure routes
routing.Routing.add_hip_default_route();
# Storage
logging.debug("Configuring state machine and storage");
hip_state_machine = HIPState.StateMachine();
keymat_storage    = HIPState.Storage();
dh_storage        = HIPState.Storage();
cipher_storage    = HIPState.Storage();
pubkey_storage    = HIPState.Storage();
state_variables   = HIPState.Storage();
key_info_storage  = HIPState.Storage();
esp_transform_storage = HIPState.Storage();

if config.config["general"]["rekey_after_packets"] > ((2<<32)-1):
	config.config["general"]["rekey_after_packets"] = (2<<32)-1;

def hip_loop():
	"""
	This loop is responsible for reading HIP packets
	from the raw socket
	"""
	logging.info("Starting the HIP loop");

	while True:
		try:
			# IP reassmebly is done automatically so we can read large enough packets
			buf = bytearray(hip_socket.recv(4*MTU));
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

			ihit = hip_packet.get_senders_hit();
			rhit = hip_packet.get_receivers_hit();

			#logging.info("Got HIP packet");
			#logging.info("Responder's HIT %s" % Utils.ipv6_bytes_to_hex_formatted(rhit));
			#logging.info("Our own HIT %s " % Utils.ipv6_bytes_to_hex_formatted(own_hit));


			#hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
			#	Utils.ipv6_bytes_to_hex_formatted(ihit));
			if Utils.is_hit_smaller(rhit, ihit):
				hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
					Utils.ipv6_bytes_to_hex_formatted(ihit));
			else:
				hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit));

			if hip_packet.get_version() != HIP.HIP_VERSION:
				logging.critical("Only HIP version 2 is supported");
				continue;

			# Check wether the destination address is our own HIT
			if not Utils.hits_equal(rhit, own_hit) and not Utils.hits_equal(rhit, [0] * 16):
				logging.critical("Not our HIT");
				logging.critical(Utils.ipv6_bytes_to_hex_formatted(rhit));
				logging.critical(Utils.ipv6_bytes_to_hex_formatted(own_hit));
				continue;

			# https://tools.ietf.org/html/rfc7401#section-5
			original_checksum = hip_packet.get_checksum();
			hip_packet.set_checksum(0x0);
			# Verify checksum
			checksum = Utils.hip_ipv4_checksum(
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

				if not firewall.allow(Utils.ipv6_bytes_to_hex_formatted(ihit), Utils.ipv6_bytes_to_hex_formatted(rhit)):
					logging.critical("Blocked by firewall...")
					continue;

				if hip_state.is_i1_sent() and Utils.is_hit_smaller(rhit, ihit):
					logging.debug("Staying in I1-SENT state");
					continue;

				if Utils.is_hit_smaller(rhit, ihit):
					state_variables.save(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit),
						HIPState.StateVariables(hip_state.get_state(), ihit, rhit, dst, src))
				else:
					state_variables.save(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit),
						HIPState.StateVariables(hip_state.get_state(), ihit, rhit, dst, src))

				st = time.time();
				
				# Check the state of the HIP protocol
				# R1 packet should be constructed only 
				# if the state is not associated
				# Need to check with the RFC

				# Construct R1 packet
				hip_r1_packet = HIP.R1Packet();
				hip_r1_packet.set_senders_hit(rhit);
				#hip_r1_packet.set_receivers_hit(ihit);
				hip_r1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r1_packet.set_version(HIP.HIP_VERSION);

				r_hash = HIT.get_responders_hash_algorithm(rhit);

				# Prepare puzzle
				irandom = PuzzleSolver.generate_irandom(r_hash.LENGTH);
				puzzle_param = HIP.PuzzleParameter(buffer = None, rhash_length = r_hash.LENGTH);
				puzzle_param.set_k_value(config.config["security"]["puzzle_difficulty"]);
				puzzle_param.set_lifetime(config.config["security"]["puzzle_lifetime_exponent"]);
				puzzle_param.set_random([0] * r_hash.LENGTH, rhash_length = r_hash.LENGTH);
				puzzle_param.set_opaque(list([0, 0]));
				
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
					logging.debug("No DH groups parameter found. Dropping I1 packet");
					continue;
				offered_dh_groups = dh_groups_param_initiator.get_groups();
				supported_dh_groups = config.config["security"]["supported_DH_groups"];
				selected_dh_group = None;
				for group in offered_dh_groups:
					if group in supported_dh_groups:
						dh_groups_param.add_groups([group]);
						selected_dh_group = group;
						break;
				if not selected_dh_group:
					logging.debug("Unsupported DH group");
					continue;

				dh = factory.DHFactory.get(selected_dh_group);
				private_key = dh.generate_private_key();
				public_key = dh.generate_public_key();
				if Utils.is_hit_smaller(rhit, ihit):
					dh_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), dh);
				else:
					dh_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), dh);
				

				dh_param = HIP.DHParameter();
				dh_param.set_group_id(selected_dh_group);
				logging.debug("DH public key: %d ", Math.bytes_to_int(dh.encode_public_key()));
				dh_param.add_public_value(dh.encode_public_key());
				logging.debug("DH public key value: %d ", Math.bytes_to_int(dh.encode_public_key()));
				logging.debug("DH public key value: %d ", Math.bytes_to_int(dh_param.get_public_value()));

				# HIP cipher parameter
				cipher_param = HIP.CipherParameter();
				cipher_param.add_ciphers(config.config["security"]["supported_ciphers"]);

				# ESP transform parameter
				esp_transform_param = HIP.ESPTransformParameter();
				esp_transform_param.add_suits(config.config["security"]["supported_esp_transform_suits"]);

				# HIP host ID parameter
				hi_param = HIP.HostIdParameter();
				hi_param.set_host_id(hi);
				# It is important to set domain ID after host ID was set
				logging.debug(di);
				hi_param.set_domain_id(di);

				logging.debug("Host ID buffer");
				logging.debug(hi_param.get_byte_buffer())

				# HIP HIT suit list parameter
				hit_suit_param = HIP.HITSuitListParameter();
				hit_suit_param.add_suits(config.config["security"]["supported_hit_suits"]);

				# Transport format list
				transport_param = HIP.TransportListParameter();
				transport_param.add_transport_formats(config.config["security"]["supported_transports"]);

				# HIP signature parameter
				signature_param = HIP.Signature2Parameter();
				#

				#Puzzle 257
				#DH groups 511
				#DH 513
				#Cipher 579
				#HI 705
				#HIT suit 715
				#Transport 2049
				#ESP transform 4095
				#Signature2 61633
				# Compute signature here
				buf = puzzle_param.get_byte_buffer() + \
						dh_groups_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer() + \
						hit_suit_param.get_byte_buffer() + \
						transport_param.get_byte_buffer() +\
						esp_transform_param.get_byte_buffer();
				
				original_length = hip_r1_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r1_packet.set_length(int(packet_length / 8));
				buf = hip_r1_packet.get_buffer() + buf;

				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());

				#logging.debug(privkey.get_key_info());
				signature = signature_alg.sign(bytearray(buf));
				logging.debug("Signature buffer")
				logging.debug(bytearray(buf));
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);				

				# Add parameters to R1 packet (order is important)
				hip_r1_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);
				# List of mandatory parameters in R1 packet...

				#Puzzle 257
				#DH groups 511
				#DH 513
				#Cipher 579
				#HI 705
				#HIT suit 715
				#Transport 2049
				#ESP transform 4095
				#Signature2 61633

				puzzle_param.set_random(irandom, r_hash.LENGTH);
				puzzle_param.set_opaque(list(Utils.generate_random(2)));
				hip_r1_packet.add_parameter(puzzle_param);
				hip_r1_packet.add_parameter(dh_groups_param);
				hip_r1_packet.add_parameter(dh_param);
				hip_r1_packet.add_parameter(cipher_param);
				hip_r1_packet.add_parameter(hi_param);
				hip_r1_packet.add_parameter(hit_suit_param);
				hip_r1_packet.add_parameter(transport_param);
				hip_r1_packet.add_parameter(esp_transform_param);
				hip_r1_packet.add_parameter(signature_param);

				# Swap the addresses
				temp = src;
				src = dst;
				dst = temp;

				# Set receiver's HIT
				hip_r1_packet.set_receivers_hit(ihit);

				# Create IPv4 packet
				ipv4_packet = IPv4.IPv4Packet();
				ipv4_packet.set_version(IPv4.IPV4_VERSION);
				ipv4_packet.set_destination_address(dst);
				ipv4_packet.set_source_address(src);
				ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
				ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
				ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

				# Calculate the checksum
				checksum = Utils.hip_ipv4_checksum(
					src, 
					dst, 
					HIP.HIP_PROTOCOL, 
					hip_r1_packet.get_length() * 8 + 8, 
					hip_r1_packet.get_buffer());
				hip_r1_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_r1_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(dst);
				logging.debug("Sending R1 packet to %s %f" % (dst_str, (time.time() - st)));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str.strip(), 0));
				# Stay in current state
			elif hip_packet.get_packet_type() == HIP.HIP_R1_PACKET:
				logging.info("R1 packet");

				# 1 0 1
				# 1 1 1
				if (hip_state.is_unassociated() 
					or hip_state.is_r2_sent() 
					or hip_state.is_established()):
					logging.debug("Dropping packet...");
					continue;

				oga = HIT.get_responders_oga_id(ihit);

				if (oga << 4) not in config.config["security"]["supported_hit_suits"]:
					logging.critical("Unsupported HIT suit");
					logging.critical("OGA %d"  % (oga));
					logging.critical(config.config["security"]["supported_hit_suits"]);
					# Send I1
					continue;

				puzzle_param       = None;
				r1_counter_param   = None;
				irandom            = None;
				opaque             = None;
				esp_transform_param = None;
				dh_param           = None;
				cipher_param       = None;
				hi_param           = None;
				hit_suit_param     = None;
				dh_groups_param    = None;
				transport_param    = None;
				echo_signed        = None;
				signature_param    = None;
				public_key         = None;
				echo_unsigned      = [];
				echo_signed_resp   = None
				parameters         = hip_packet.get_parameters();
				
				st = time.time();

				hip_r1_packet = HIP.R1Packet();
				hip_r1_packet.set_senders_hit(hip_packet.get_senders_hit());
				#hip_r1_packet.set_receivers_hit(ihit);
				hip_r1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r1_packet.set_version(HIP.HIP_VERSION);

				r_hash = HIT.get_responders_hash_algorithm(ihit);
				logging.debug(r_hash);

				for parameter in parameters:
					if isinstance(parameter, HIP.DHGroupListParameter):
						logging.debug("DH groups parameter");
						dh_groups_param = parameter;
					if isinstance(parameter, HIP.R1CounterParameter):
						logging.debug("R1 counter");
						r1_counter_param = parameter;
					if isinstance(parameter, HIP.PuzzleParameter):
						logging.debug("Puzzle parameter");
						puzzle_param = parameter;
						irandom = puzzle_param.get_random(rhash_length = r_hash.LENGTH);
						opaque = puzzle_param.get_opaque();
						puzzle_param.set_random([0] * r_hash.LENGTH, r_hash.LENGTH);
						puzzle_param.set_opaque(list([0, 0]));
					if isinstance(parameter, HIP.DHParameter):	
						logging.debug("DH parameter");
						dh_param = parameter;
					if isinstance(parameter, HIP.HostIdParameter):
						logging.debug("DI type: %d " % parameter.get_di_type());
						logging.debug("DI value: %s " % parameter.get_domain_id());
						logging.debug("Host ID");

						hi_param = parameter;
						
						logging.debug("Host ID buffer");
						logging.debug(list(hi_param.get_byte_buffer()))
						
						# Check the algorithm and construct the HI based on the proposed algorithm
						if hi_param.get_algorithm() == 0x5: #RSA
							responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
						elif hi_param.get_algorithm() == 0x7: #ECDSA
							responder_hi = ECDSAHostID.from_byte_buffer(hi_param.get_host_id());
						elif hi_param.get_algorithm() == 0x9: #ECDSA LOW
							responder_hi = ECDSALowHostID.from_byte_buffer(hi_param.get_host_id());
						else:
							raise Exception("Invalid signature algorithm");

						oga = HIT.get_responders_oga_id(ihit);
						logging.debug("Responder's OGA ID %d" % (oga));
						logging.debug(list(responder_hi.to_byte_array()));
						responders_hit = HIT.get(responder_hi.to_byte_array(), oga);
						logging.debug(list(responders_hit))
						logging.debug(list(ihit))
						logging.debug(list(own_hit))
						if not Utils.hits_equal(ihit, responders_hit):
							logging.critical("Invalid HIT");
							raise Exception("Invalid HIT");
						
						if isinstance(responder_hi, RSAHostID): #RSA
							responders_public_key = RSAPublicKey.load_from_params(
								responder_hi.get_exponent(), 
								responder_hi.get_modulus());
						elif isinstance(responder_hi, ECDSAHostID): #ECDSA
							responders_public_key = ECDSAPublicKey.load_from_params(
								responder_hi.get_curve_id(), 
								responder_hi.get_x(),
								responder_hi.get_y());
						elif isinstance(responder_hi, ECDSALowHostID): #ECDSA LOW
							responders_public_key = ECDSALowPublicKey.load_from_params(
								responder_hi.get_curve_id(), 
								responder_hi.get_x(),
								responder_hi.get_y());
						else:
							raise Exception("Invalid signature algorithm");
						
						pubkey_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
							Utils.ipv6_bytes_to_hex_formatted(rhit), 
							responders_public_key);
					if isinstance(parameter, HIP.HITSuitListParameter):
						logging.debug("HIT suit list");
						hit_suit_param = parameter;
					if isinstance(parameter, HIP.TransportListParameter):
						logging.debug("Transport parameter");
						logging.debug(parameter.get_transport_formats());
						transport_param = parameter;
					if isinstance(parameter, HIP.Signature2Parameter):
						logging.debug("Signature parameter");
						signature_param = parameter;
					if isinstance(parameter, HIP.EchoRequestSignedParameter):
						logging.debug("Echo request signed parameter");
						echo_signed = parameter;
						echo_signed_resp = HIP.EchoResponseSignedParameter();
						echo_signed_resp.add_opaque_data(parameter.get_opaque_data());
					if isinstance(parameter, HIP.EchoRequestUnsignedParameter):
						logging.debug("Echo request unsigned parameter");
						echo_unsigned_param = HIP.EchoResponseUnsignedParameter();
						echo_unsigned_param.add_opaque_data(parameter.get_opaque_data());
						echo_unsigned.append(echo_unsigned_param);
					if isinstance(parameter, HIP.CipherParameter):
						logging.debug("Ciphers");
						cipher_param = parameter;
					if isinstance(parameter, HIP.ESPTransformParameter):
						logging.debug("ESP transform");
						esp_transform_param = parameter;

				if not puzzle_param:
					logging.critical("Missing puzzle parameter");
					continue;
				if not dh_param:
					logging.critical("Missing DH parameter");
					continue;
				if not cipher_param:
					logging.critical("Missing cipher parameter");
					continue;
				if not esp_transform_param:
					logging.critical("Missing ESP transform parameter");
					continue;
				if not hi_param:
					logging.critical("Missing HI parameter");
					continue;
				if not hit_suit_param:
					logging.critical("Missing HIT suit parameter");
					continue;
				if not dh_groups_param:
					logging.critical("Missing DH groups parameter");
					continue;
				if not transport_param:
					logging.critical("Missing transport parameter");
					continue;
				if not signature_param:
					logging.critical("Missing signature parameter");
					continue;
				if not dh_param.get_group_id() in dh_groups_param.get_groups():
					logging.critical("Manipulation of DH group");
					# Change the state to unassociated... drop the BEX
					continue;
				
				start_time = time.time();
				jrandom = PuzzleSolver.solve_puzzle(irandom, hip_packet.get_receivers_hit(), hip_packet.get_senders_hit(), puzzle_param.get_k_value(), r_hash)
				#if PuzzleSolver.verify_puzzle(irandom, jrandom, hip_packet.get_receivers_hit(), hip_packet.get_senders_hit(), puzzle_param.get_k_value(), r_hash):
				logging.debug("Puzzle was solved and verified....");
				end_time = time.time();
				if (end_time - start_time) > (2 << (puzzle_param.get_lifetime() - 32)):
					logging.critical("Maximum time to solve the puzzle exceeded. Dropping the packet...");
					# Abandon the BEX
					hip_state.unassociated();
					continue;

				buf = [];

				if r1_counter_param:
					buf += r1_counter_param.get_byte_buffer();

				#R1 counter 8
				#Puzzle 257
				#DH groups 511
				#DH 513
				#Cipher 579
				#HI 705
				#HIT suit 715
				#Echo signed 897
				#Transport 2049
				#ESP transform 4095
				#Signature2 61633
				if not echo_signed:
					buf += puzzle_param.get_byte_buffer() + \
						dh_groups_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer() + \
						hit_suit_param.get_byte_buffer() + \
						transport_param.get_byte_buffer() + \
						esp_transform_param.get_byte_buffer();
				else:
					buf += puzzle_param.get_byte_buffer() + \
						dh_groups_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer() + \
						hit_suit_param.get_byte_buffer() + \
						echo_signed.get_byte_buffer() + \
						transport_param.get_byte_buffer() + \
						esp_transform_param.get_byte_buffer();
				original_length = hip_r1_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r1_packet.set_length(int(packet_length / 8));
				buf = bytearray(hip_r1_packet.get_buffer()) + bytearray(buf);

				responder_hi_param = hi_param

				#signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				if isinstance(responders_public_key, RSAPublicKey):
					signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSAPublicKey):
					signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
					logging.debug(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSALowPublicKey):
					signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

				#logging.debug(privkey.get_key_info());
				logging.debug(bytearray(buf));
				if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
					logging.critical("Invalid signature in R1 packet. Dropping the packet");
					continue;
				
				logging.debug("DH public key value: %d ", Math.bytes_to_int(dh_param.get_public_value()));
				
				offered_dh_groups = dh_groups_param.get_groups();
				supported_dh_groups = config.config["security"]["supported_DH_groups"];
				selected_dh_group = None;
				for group in supported_dh_groups:
					if group in offered_dh_groups:
						selected_dh_group = group;
						break;
				if not selected_dh_group:
					logging.critical("Unsupported DH group");
					# Transition to unassociated state
					raise Exception("Unsupported DH group");

				dh = factory.DHFactory.get(selected_dh_group);
				private_key  = dh.generate_private_key();
				public_key_i = dh.generate_public_key();
				public_key_r = dh.decode_public_key(dh_param.get_public_value());
				shared_secret = dh.compute_shared_secret(public_key_r);

				logging.debug("Secret key %d" % shared_secret);

				if Utils.is_hit_smaller(rhit, ihit):
					dh_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), dh);
				else:
					dh_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), dh);
				#dh_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
				#	Utils.ipv6_bytes_to_hex_formatted(rhit), dh);

				info = Utils.sort_hits(ihit, rhit);
				salt = irandom + jrandom;
				hmac_alg  = HIT.get_responders_oga_id(ihit);

				key_info = HIPState.KeyInfo(info, salt, dh.ALG_ID);

				if Utils.is_hit_smaller(rhit, ihit):
					key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), key_info);
				else:
					key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), key_info);

				offered_ciphers = cipher_param.get_ciphers();
				supported_ciphers = config.config["security"]["supported_ciphers"];
				selected_cipher = None;

				for cipher in offered_ciphers:
					if cipher in supported_ciphers:
						selected_cipher = cipher;
						break;

				if not selected_cipher:
					logging.critical("Unsupported cipher");
					# Transition to unassociated state
					raise Exception("Unsupported cipher");

				offered_esp_transforms = esp_transform_param.get_suits();
				supported_esp_transform_suits = config.config["security"]["supported_esp_transform_suits"];
				selected_esp_transform = None;
				for suit in offered_esp_transforms:
					if suit in supported_esp_transform_suits:
						selected_esp_transform = suit;
						break;

				if not selected_esp_transform:
					logging.critical("Unsupported ESP transform suit");
					raise Exception("Unsupported ESP transform suit");

				if Utils.is_hit_smaller(rhit, ihit):
					esp_transform_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), [selected_esp_transform]);
				else:
					esp_transform_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), [selected_esp_transform]);

				logging.debug("...............................")
				logging.debug(Utils.ipv6_bytes_to_hex_formatted(rhit))
				logging.debug(Utils.ipv6_bytes_to_hex_formatted(ihit))
				logging.debug("...............................")

				if Utils.is_hit_smaller(rhit, ihit):
					cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), selected_cipher);
				else:
					cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), selected_cipher);
				#cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
				#	Utils.ipv6_bytes_to_hex_formatted(rhit), selected_cipher);
				keymat_length_in_octets = Utils.compute_keymat_length(hmac_alg, selected_cipher);
				keymat = Utils.kdf(hmac_alg, salt, Math.int_to_bytes(shared_secret), info, keymat_length_in_octets);

				if Utils.is_hit_smaller(rhit, ihit):
					keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), keymat);
				else:
					keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), keymat);
				

				logging.debug("Processing R1 packet %f" % (time.time() - st));

				st = time.time();

				# Transition to I2 state
				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(rhit);
				hip_i2_packet.set_receivers_hit(ihit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);

				solution_param = HIP.SolutionParameter(buffer = None, rhash_length = r_hash.LENGTH);
				solution_param.set_k_value(puzzle_param.get_k_value());
				solution_param.set_opaque(opaque);
				solution_param.set_random(irandom, r_hash.LENGTH);
				solution_param.set_solution(jrandom, r_hash.LENGTH);

				dh_param = HIP.DHParameter();
				dh_param.set_group_id(selected_dh_group);
				dh_param.add_public_value(dh.encode_public_key());

				cipher_param = HIP.CipherParameter();
				cipher_param.add_ciphers([selected_cipher]);

				esp_transform_param = HIP.ESPTransformParameter();
				esp_transform_param.add_suits([selected_esp_transform]);

				keymat_index = Utils.compute_hip_keymat_length(hmac_alg, selected_cipher);

				esp_info_param = HIP.ESPInfoParameter();
				esp_info_param.set_keymat_index(keymat_index);
				esp_info_param.set_new_spi(Math.bytes_to_int(Utils.generate_random(HIP.HIP_ESP_INFO_NEW_SPI_LENGTH)));

				# Keying material generation
				# https://tools.ietf.org/html/rfc7402#section-7

				hi_param = HIP.HostIdParameter();
				hi_param.set_host_id(hi);
				hi_param.set_domain_id(di);

				transport_param = HIP.TransportListParameter();
				transport_param.add_transport_formats(config.config["security"]["supported_transports"]);

				mac_param = HIP.MACParameter();

				#R1 Counter 8
				#ESP info 65
				#Solution 321
				#DH 513
				#Cipher 579
				#HI 705
				#Echo 961
				#Transport 2049
				#Esp transform 4095
				#MAC 61505

				# Compute HMAC here
				if r1_counter_param:
					buf = r1_counter_param.get_byte_buffer();
					buf += esp_info_param.get_byte_buffer();
				else:
					buf = esp_info_param.get_byte_buffer();
				
				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed:
					buf += echo_signed.get_byte_buffer();

				buf += transport_param.get_byte_buffer();
				buf += esp_transform_param.get_byte_buffer()

				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = hip_i2_packet.get_buffer() + buf;
				
				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, ihit, rhit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);
				mac_param.set_hmac(hmac.digest(bytearray(buf)));

				# Compute signature here
				
				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(rhit);
				hip_i2_packet.set_receivers_hit(ihit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);
				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				#R1 Counter 8
				#ESP info 65
				#Solution 321
				#DH 513
				#Cipher 579
				#HI 705
				#Echo 961
				#Transport 2049
				#Esp transform 4095
				#MAC 61505

				# Compute HMAC here
				if r1_counter_param:
					buf = r1_counter_param.get_byte_buffer();
					buf += esp_info_param.get_byte_buffer();
				else:
					buf = esp_info_param.get_byte_buffer();
				
				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed_resp:
					buf += echo_signed_resp.get_byte_buffer();

				buf += transport_param.get_byte_buffer();
				buf += esp_transform_param.get_byte_buffer() + \
						mac_param.get_byte_buffer()
				
				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = hip_i2_packet.get_buffer() + buf;
				#signature_alg = RSASHA256Signature(privkey.get_key_info());
				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());

				signature = signature_alg.sign(bytearray(buf));

				signature_param = HIP.SignatureParameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				total_param_length = 0;

				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(rhit);
				hip_i2_packet.set_receivers_hit(ihit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);
				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				#R1 Counter 8
				#ESP info 65
				#Solution 321
				#DH 513
				#Cipher 579
				#HI 705
				#Echo 961
				#Transport 2049
				#Esp transform 4095
				#MAC 61505

				if r1_counter_param:
					hip_i2_packet.add_parameter(r1_counter_param);
				hip_i2_packet.add_parameter(esp_info_param);
				hip_i2_packet.add_parameter(solution_param);
				hip_i2_packet.add_parameter(dh_param);
				hip_i2_packet.add_parameter(cipher_param);
				hip_i2_packet.add_parameter(hi_param);
				if echo_signed_resp:
					hip_i2_packet.add_parameter(echo_signed_resp);
				hip_i2_packet.add_parameter(transport_param);
				hip_i2_packet.add_parameter(esp_transform_param);
				hip_i2_packet.add_parameter(mac_param);
				hip_i2_packet.add_parameter(signature_param);
				for unsigned_param in echo_unsigned:
					hip_i2_packet.add_parameter(unsigned_param);

				# Swap the addresses
				temp = src;
				src = dst;
				dst = temp;

				# Calculate the checksum
				checksum = Utils.hip_ipv4_checksum(
					src, 
					dst, 
					HIP.HIP_PROTOCOL, 
					hip_i2_packet.get_length() * 8 + 8, 
					hip_i2_packet.get_buffer());
				hip_i2_packet.set_checksum(checksum);

				buf = hip_i2_packet.get_buffer();
				
				total_length = len(buf);
				fragment_len = HIP.HIP_FRAGMENT_LENGTH;
				num_of_fragments = int(ceil(total_length / fragment_len))
				offset = 0;
				#for i in range(0, num_of_fragments):
				# Create IPv4 packet
				ipv4_packet = IPv4.IPv4Packet();
				ipv4_packet.set_version(IPv4.IPV4_VERSION);
				ipv4_packet.set_destination_address(dst);
				ipv4_packet.set_source_address(src);
				ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
				ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
				ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
				
				# Fragment the packet
				#ipv4_packet.set_fragment_offset(offset);
				#if num_of_fragments > 1 and num_of_fragments - 1 != i:
				#	# Set flag more fragments to follow
				#		ipv4_packet.set_flags(0x1)	
				#	ipv4_packet.set_payload(buf[offset:offset + fragment_len]);
				#	offset += fragment_len;
				#	# Send the packet
				ipv4_packet.set_payload(buf);
				dst_str = Utils.ipv4_bytes_to_string(dst);
					
				logging.debug(list(ipv4_packet.get_buffer()));

				logging.debug("Sending I2 packet to %s %d" % (dst_str, len(ipv4_packet.get_buffer())));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str.strip(), 0));

				if Utils.is_hit_smaller(rhit, ihit):
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit));
				sv.i2_packet = ipv4_packet;

				if hip_state.is_i1_sent() or hip_state.is_closing() or hip_state.is_closed():
					hip_state.i2_sent();
			elif hip_packet.get_packet_type() == HIP.HIP_I2_PACKET:
				logging.info("I2 packet");
				st = time.time();

				solution_param     = None;
				r1_counter_param   = None;
				dh_param           = None;
				cipher_param       = None;
				esp_transform_param = None;
				esp_info_param     = None;
				hi_param           = None;
				transport_param    = None;
				mac_param          = None;
				signature_param    = None;
				echo_signed        = None;
				parameters         = hip_packet.get_parameters();
				iv_length          = None;
				encrypted_param    = None;

				initiators_spi     = None;
				initiators_keymat_index = None;

				for parameter in parameters:
					if isinstance(parameter, HIP.ESPInfoParameter):
						logging.debug("ESP info parameter")
						esp_info_param = parameter;
					if isinstance(parameter, HIP.R1CounterParameter):
						logging.debug("R1 counter");
						r1_counter_param = parameter;
					if isinstance(parameter, HIP.SolutionParameter):
						logging.debug("Puzzle solution parameter");
						solution_param = parameter;
					if isinstance(parameter, HIP.DHParameter):	
						logging.debug("DH parameter");
						dh_param = parameter;
					if isinstance(parameter, HIP.EncryptedParameter):
						logging.debug("Encrypted parameter");
						encrypted_param = parameter;
					if isinstance(parameter, HIP.HostIdParameter):
						logging.debug("Host ID");
						hi_param = parameter;
						#responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
						#if hi_param.get_algorithm() != config.config["security"]["sig_alg"]:
						#	logging.critical("Invalid signature algorithm");
						#	continue;
						if hi_param.get_algorithm() == 0x5: #RSA
							responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
						elif hi_param.get_algorithm() == 0x7: #ECDSA
							responder_hi = ECDSAHostID.from_byte_buffer(hi_param.get_host_id());
						elif hi_param.get_algorithm() == 0x9: #ECDSA LOW
							responder_hi = ECDSALowHostID.from_byte_buffer(hi_param.get_host_id());
						else:
							raise Exception("Invalid signature algorithm");
						oga = HIT.get_responders_oga_id(ihit);
						logging.debug("OGA ID %d " % (oga));
						responders_hit = HIT.get(responder_hi.to_byte_array(), oga);
						logging.debug(list(rhit));
						logging.debug(list(ihit));
						logging.debug(list(responders_hit));
						if not Utils.hits_equal(ihit, responders_hit):
							logging.critical("Invalid HIT");
							raise Exception("Invalid HIT");

						if isinstance(responder_hi, RSAHostID): #RSA
							responders_public_key = RSAPublicKey.load_from_params(
								responder_hi.get_exponent(), 
								responder_hi.get_modulus());
						elif isinstance(responder_hi, ECDSAHostID): #ECDSA
							responders_public_key = ECDSAPublicKey.load_from_params(
								responder_hi.get_curve_id(), 
								responder_hi.get_x(),
								responder_hi.get_y());
						elif isinstance(responder_hi, ECDSALowHostID): #ECDSA LOW
							responders_public_key = ECDSALowPublicKey.load_from_params(
								responder_hi.get_curve_id(), 
								responder_hi.get_x(),
								responder_hi.get_y());
						else:
							raise Exception("Invalid signature algorithm");

						pubkey_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
							Utils.ipv6_bytes_to_hex_formatted(rhit), 
							responders_public_key);
					if isinstance(parameter, HIP.TransportListParameter):
						logging.debug("Transport parameter");
						transport_param = parameter;
					if isinstance(parameter, HIP.SignatureParameter):
						logging.debug("Signature parameter");
						signature_param = parameter;
					if isinstance(parameter, HIP.CipherParameter):
						logging.debug("Ciphers parameter");
						cipher_param = parameter;
					if isinstance(parameter, HIP.ESPTransformParameter):
						logging.debug("ESP transform parameter");
						esp_transform_param = parameter;
					if isinstance(parameter, HIP.MACParameter):
						logging.debug("MAC parameter");	
						mac_param = parameter;
					if isinstance(parameter, HIP.EchoResponseSignedParameter):
						logging.debug("Echo response signed");
						echo_signed = parameter;
				if not solution_param:
					logging.critical("Missing solution parameter");
					continue;
				if not dh_param:
					logging.critical("Missing DH parameter");
					continue;
				if not cipher_param:
					logging.critical("Missing cipher parameter");
					continue;
				if not esp_info_param:
					logging.critical("Missing ESP info parameter");
					continue;
				if not hi_param:
					logging.critical("Missing HI parameter");
					continue;
				if not transport_param:
					logging.critical("Missing transport parameter");
					continue;
				if not signature_param:
					logging.critical("Missing signature parameter");
					continue;
				if not mac_param:
					logging.critical("Missing MAC parameter");
					continue;
				
				oga = HIT.get_responders_oga_id(rhit);

				if (oga << 4) not in config.config["security"]["supported_hit_suits"]:
					logging.critical("Unsupported HIT suit");
					logging.critical("OGA %d"  % (oga));
					logging.critical(config.config["security"]["supported_hit_suits"]);
					continue;

				if hip_state.is_i2_sent():
					if Utils.is_hit_smaller(rhit, ihit):
						logging.debug("Dropping I2 packet...");
						continue;

				r_hash = HIT.get_responders_hash_algorithm(rhit);
				jrandom = solution_param.get_solution(r_hash.LENGTH);
				irandom = solution_param.get_random(r_hash.LENGTH);
				if not PuzzleSolver.verify_puzzle(
					irandom, 
					jrandom, 
					hip_packet.get_senders_hit(), 
					hip_packet.get_receivers_hit(), 
					solution_param.get_k_value(), r_hash):
					logging.debug("Puzzle was not solved....");
					continue;
				logging.debug("Puzzle was solved");


				if Utils.is_hit_smaller(rhit, ihit):
					dh = dh_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					dh = dh_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit));
				#dh_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
				#	Utils.ipv6_bytes_to_hex_formatted(rhit));

				public_key_r = dh.decode_public_key(dh_param.get_public_value());
				shared_secret = dh.compute_shared_secret(public_key_r);
				logging.debug("Secret key %d" % shared_secret);

				info = Utils.sort_hits(ihit, rhit);
				salt = irandom + jrandom;
				hmac_alg  = HIT.get_responders_oga_id(rhit);

				key_info = HIPState.KeyInfo(info, salt, dh.ALG_ID);

				if Utils.is_hit_smaller(rhit, ihit):
					key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), key_info);
				else:
					key_info_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), key_info);

				offered_ciphers = cipher_param.get_ciphers();
				supported_ciphers = config.config["security"]["supported_ciphers"];
				selected_cipher = None;

				for cipher in offered_ciphers:
					if cipher in supported_ciphers:
						selected_cipher = cipher;
						break;

				if not selected_cipher:
					logging.critical("Unsupported cipher");
					# Transition to unassociated state
					raise Exception("Unsupported cipher");

				if len(esp_transform_param.get_suits()) == 0:
					logging.critical("ESP transform suit was not negotiated.")
					raise Exception("ESP transform suit was not negotiated.");

				selected_esp_transform = esp_transform_param.get_suits()[0];

				initiators_spi = esp_info_param.get_new_spi();
				initiators_keymat_index = esp_info_param.get_keymat_index();

				keymat_length_in_octets = Utils.compute_keymat_length(hmac_alg, selected_cipher);
				keymat = Utils.kdf(hmac_alg, salt, Math.int_to_bytes(shared_secret), info, keymat_length_in_octets);

				if Utils.is_hit_smaller(rhit, ihit):
					keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), keymat);
				else:
					keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), keymat);
				#keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
				#	Utils.ipv6_bytes_to_hex_formatted(rhit), keymat);

				if Utils.is_hit_smaller(rhit, ihit):
					cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit), selected_cipher);
				else:
					cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit), selected_cipher);
				#cipher_storage.save(Utils.ipv6_bytes_to_hex_formatted(ihit), 
				#	Utils.ipv6_bytes_to_hex_formatted(rhit), selected_cipher);

				if encrypted_param:
					(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, ihit, rhit);
					cipher = SymmetricCiphersFactory.get(selected_cipher);
					iv_length = cipher.BLOCK_SIZE;
					iv = encrypted_param.get_iv(iv_length);
					data = encrypted_param.get_encrypted_data(iv_length);
					host_id_data = cipher.decrypt(aes_key, iv, data);
					hi_param = HIP.HostIdParameter(host_id_data);
					#responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
					#if hi_param.get_algorithm() != config.config["security"]["sig_alg"]:
					#	logging.critical("Invalid signature algorithm");
					#	raise Exception("Invalid signature algorithm");
					if hi_param.get_algorithm() == 0x5: #RSA
						responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
					elif hi_param.get_algorithm() == 0x7: #ECDSA
						responder_hi = ECDSAHostID.from_byte_buffer(hi_param.get_host_id());
					elif hi_param.get_algorithm() == 0x9: #ECDSA LOW
						responder_hi = ECDSALowHostID.from_byte_buffer(hi_param.get_host_id());
					else:
						raise Exception("Invalid signature algorithm");
					oga = HIT.get_responders_oga_id(rhit);
					responders_hit = HIT.get(responder_hi.to_byte_array(), oga);
					if not Utils.hits_equal(ihit, responders_hit):
						logging.critical("Not our HIT");
						raise Exception("Invalid HIT");
					
					if isinstance(responder_hi, RSAHostID): #RSA
						responders_public_key = RSAPublicKey.load_from_params(
							responder_hi.get_exponent(), 
							responder_hi.get_modulus());
					elif isinstance(responder_hi, ECDSAHostID): #ECDSA
						responders_public_key = ECDSAPublicKey.load_from_params(
							responder_hi.get_curve_id(), 
							responder_hi.get_x(),
							responder_hi.get_y());
					elif isinstance(responder_hi, ECDSALowHostID): #ECDSA LOW
						responders_public_key = ECDSALowPublicKey.load_from_params(
							responder_hi.get_curve_id(), 
							responder_hi.get_x(),
							responder_hi.get_y());
					else:
						raise Exception("Invalid signature algorithm");

				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(ihit);
				hip_i2_packet.set_receivers_hit(rhit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);
				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				#R1 Counter 8
				#ESP info 65
				#Solution 321
				#DH 513
				#Cipher 579
				#HI 705
				#Echo 961
				#Transport 2049
				#Esp transform 4095
				#MAC 61505

				# Compute HMAC here
				if r1_counter_param:
					buf = r1_counter_param.get_byte_buffer();
					buf += esp_info_param.get_byte_buffer();
				else:
					buf = esp_info_param.get_byte_buffer();

				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed:
					buf += echo_signed.get_byte_buffer();

				buf += transport_param.get_byte_buffer();
				buf += esp_transform_param.get_byte_buffer();

				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = list(hip_i2_packet.get_buffer()) + list(buf);
				
				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, rhit, ihit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				if list(hmac.digest(bytearray(buf))) != list(mac_param.get_hmac()):
					logging.critical("Invalid HMAC. Dropping the packet");
					continue;

				# Compute signature here
				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(ihit);
				hip_i2_packet.set_receivers_hit(rhit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);
				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				#R1 Counter 8
				#ESP info 65
				#Solution 321
				#DH 513
				#Cipher 579
				#HI 705
				#Echo 961
				#Transport 2049
				#Esp transform 4095
				#MAC 61505

				if r1_counter_param:
					buf = r1_counter_param.get_byte_buffer();
					buf += esp_info_param.get_byte_buffer();
				else:
					buf = esp_info_param.get_byte_buffer();
				
				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed:
					buf += echo_signed.get_byte_buffer();

				buf += transport_param.get_byte_buffer() + \
						esp_transform_param.get_byte_buffer() + \
						mac_param.get_byte_buffer();
				
				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = list(hip_i2_packet.get_buffer()) + list(buf);

				#signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				if isinstance(responders_public_key, RSAPublicKey):
					signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSAPublicKey):
					signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSALowPublicKey):
					signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

				if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
					logging.critical("Invalid signature. Dropping the packet");
				else:
					logging.debug("Signature is correct");

				logging.debug("Processing I2 packet %f" % (time.time() - st));
				
				st = time.time();

				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(rhit);
				hip_r2_packet.set_receivers_hit(ihit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				keymat_index = Utils.compute_hip_keymat_length(hmac_alg, selected_cipher);
				responders_spi = Math.bytes_to_int(Utils.generate_random(HIP.HIP_ESP_INFO_NEW_SPI_LENGTH));

				if initiators_keymat_index != keymat_index:
					raise Exception("Keymat index should match....")

				# ESP info 65
				# HI 705
				
				esp_info_param = HIP.ESPInfoParameter();
				esp_info_param.set_keymat_index(keymat_index);
				esp_info_param.set_new_spi(responders_spi);

				hip_r2_packet.add_parameter(esp_info_param);

				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, ihit, rhit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				own_hi_param = HIP.HostIdParameter();
				own_hi_param.set_host_id(hi);
				own_hi_param.set_domain_id(di);

				hip_r2_packet.add_parameter(own_hi_param)

				mac_param = HIP.MAC2Parameter();
				mac_param.set_hmac(hmac.digest(bytearray(hip_r2_packet.get_buffer())));

				# Compute signature here
				
				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(rhit);
				hip_r2_packet.set_receivers_hit(ihit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				buf = esp_info_param.get_byte_buffer();

				buf += mac_param.get_byte_buffer();				
				original_length = hip_r2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r2_packet.set_length(int(packet_length / 8));
				buf = hip_r2_packet.get_buffer() + buf;
				#signature_alg = RSASHA256Signature(privkey.get_key_info());
				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());

				signature = signature_alg.sign(bytearray(buf));

				signature_param = HIP.Signature2Parameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				hip_r2_packet.add_parameter(esp_info_param);
				hip_r2_packet.add_parameter(mac_param);
				hip_r2_packet.add_parameter(signature_param);
				
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
				checksum = Utils.hip_ipv4_checksum(
					src, 
					dst, 
					HIP.HIP_PROTOCOL, 
					hip_r2_packet.get_length() * 8 + 8, 
					hip_r2_packet.get_buffer());
				hip_r2_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_r2_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(dst);
				src_str = Utils.ipv4_bytes_to_string(src);
				
				# Transition to an Established state
				logging.debug("Current system state is %s" % (str(hip_state)));
				
				if (hip_state.is_established() 
					or hip_state.is_unassociated() 
					or hip_state.is_i1_sent() 
					or hip_state.is_i2_sent() 
					or hip_state.is_r2_sent()
					or hip_state.is_closing()
					or hip_state.is_closed()):
					hip_state.r2_sent();
					logging.debug("Sending R2 packet to %s %f" % (dst_str, time.time() - st));
					hip_socket.sendto(
						bytearray(ipv4_packet.get_buffer()), 
						(dst_str.strip(), 0));

				logging.debug("Setting SA records...");

				#selected_esp_transform = esp_transform_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
				#	Utils.ipv6_bytes_to_hex_formatted(rhit))[0];

				logging.debug("Using the following ESP transform....")
				logging.debug(selected_esp_transform)

				(cipher, hmac) = ESPTransformFactory.get(selected_esp_transform);

				(cipher_key, hmac_key) = Utils.get_keys_esp(
					keymat, 
					keymat_index, 
					hmac.ALG_ID, 
					cipher.ALG_ID, 
					ihit, rhit);
				sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, src, dst);
				sa_record.set_spi(responders_spi);
				ip_sec_sa.add_record(Utils.ipv6_bytes_to_hex_formatted(rhit), 
					Utils.ipv6_bytes_to_hex_formatted(ihit), sa_record);

				(cipher_key, hmac_key) = Utils.get_keys_esp(
					keymat, 
					keymat_index, 
					hmac.ALG_ID, 
					cipher.ALG_ID, 
					rhit, ihit);
				#(aes_key, hmac_key) = Utils.get_keys_esp(keymat, hmac_alg, selected_cipher, rhit, ihit);
				#sa_record = SA.SecurityAssociationRecord(selected_cipher, hmac_alg, aes_key, hmac_key, rhit, ihit);
				sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, rhit, ihit);
				sa_record.set_spi(initiators_spi);
				ip_sec_sa.add_record(dst_str, src_str, sa_record);
				
				if Utils.is_hit_smaller(rhit, ihit):
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit));
				
				sv.ec_complete_timeout = time.time() + config.config["general"]["EC"];

			elif hip_packet.get_packet_type() == HIP.HIP_R2_PACKET:
				
				if (hip_state.is_unassociated() 
					or hip_state.is_i1_sent() 
					or hip_state.is_r2_sent() 
					or hip_state.is_established()
					or hip_state.is_closing()
					or hip_state.is_closed()):
					logging.debug("Dropping the packet");
					continue;

				st = time.time();

				logging.info("R2 packet");
				
				hmac_alg  = HIT.get_responders_oga_id(ihit);

				if Utils.is_hit_smaller(rhit, ihit):
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				if Utils.is_hit_smaller(rhit, ihit):
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				#keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
				#	Utils.ipv6_bytes_to_hex_formatted(rhit));

				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, rhit, ihit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);
				parameters       = hip_packet.get_parameters();
				
				esp_info_param  = None;
				hmac_param      = None;
				signature_param = None;

				initiators_spi          = None;
				responders_spi          = None;
				keymat_index            = None;

				for parameter in parameters:
					if isinstance(parameter, HIP.ESPInfoParameter):
						logging.debug("ESP info parameter");
						esp_info_param = parameter;
					if isinstance(parameter, HIP.Signature2Parameter):
						logging.debug("Signature2 parameter");
						signature_param = parameter;
					if isinstance(parameter, HIP.MAC2Parameter):
						logging.debug("MAC2 parameter");	
						hmac_param = parameter;
				
				if not esp_info_param:
					logging.critical("Missing ESP info parameter");
					continue;

				if not hmac_param:
					logging.critical("Missing HMAC parameter");
					continue;

				if not signature_param:
					logging.critical("Missing signature parameter");
					continue;

				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(ihit);
				hip_r2_packet.set_receivers_hit(rhit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				hip_r2_packet.add_parameter(esp_info_param);
				hip_r2_packet.add_parameter(responder_hi_param);

				if list(hmac.digest(bytearray(hip_r2_packet.get_buffer()))) != list(hmac_param.get_hmac()):
					logging.critical("Invalid HMAC. Dropping the packet");
					continue;
				else:
					logging.debug("HMAC is ok. Continue with signature");

				buf = [];
				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(ihit);
				hip_r2_packet.set_receivers_hit(rhit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				#hip_r2_packet.add_parameter(hmac_param);
				buf = list(esp_info_param.get_byte_buffer());

				buf += list(hmac_param.get_byte_buffer());
				original_length = hip_r2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r2_packet.set_length(int(packet_length / 8));
				buf = hip_r2_packet.get_buffer() + buf;

				responders_public_key = pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
							Utils.ipv6_bytes_to_hex_formatted(rhit));
				#signature_alg = RSASHA256Signature(responders_public_key.get_key_info());

				if isinstance(responders_public_key, RSAPublicKey):
					signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSAPublicKey):
					signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSALowPublicKey):
					signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());
				
				if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
					logging.critical("Invalid signature. Dropping the packet");
				else:
					logging.debug("Signature is correct");

				responders_spi = esp_info_param.get_new_spi();
				keymat_index = esp_info_param.get_keymat_index();

				logging.debug("Processing R2 packet %f" % (time.time() - st));
				logging.debug("Ending HIP BEX %f" % (time.time()));

				dst_str = Utils.ipv4_bytes_to_string(dst);
				src_str = Utils.ipv4_bytes_to_string(src);

				logging.debug("Setting SA records... %s - %s" % (src_str, dst_str));

				if Utils.is_hit_smaller(rhit, ihit):
					selected_esp_transform = esp_transform_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit))[0];
				else:
					selected_esp_transform = esp_transform_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit))[0];

				(cipher, hmac) = ESPTransformFactory.get(selected_esp_transform);

				logging.debug(hmac.ALG_ID);
				logging.debug(cipher.ALG_ID);
				(cipher_key, hmac_key) = Utils.get_keys_esp(
					keymat, 
					keymat_index, 
					hmac.ALG_ID, 
					cipher.ALG_ID, 
					ihit, rhit);
				sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, dst, src);
				sa_record.set_spi(responders_spi);
				ip_sec_sa.add_record(Utils.ipv6_bytes_to_hex_formatted(rhit), 
					Utils.ipv6_bytes_to_hex_formatted(ihit), sa_record);

				(cipher_key, hmac_key) = Utils.get_keys_esp(
					keymat, 
					keymat_index, 
					hmac.ALG_ID, 
					cipher.ALG_ID, 
					rhit, ihit);
				
				sa_record = SA.SecurityAssociationRecord(cipher.ALG_ID, hmac.ALG_ID, cipher_key, hmac_key, rhit, ihit);
				sa_record.set_spi(responders_spi);
				ip_sec_sa.add_record(src_str, dst_str, sa_record);

				# Transition to an Established state
				hip_state.established();
				if Utils.is_hit_smaller(rhit, ihit):
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit));
				sv.data_timeout = time.time() + config.config["general"]["UAL"];
				#sv.state = HIPState.HIP_STATE_ESTABLISHED;
			elif hip_packet.get_packet_type() == HIP.HIP_UPDATE_PACKET:
				logging.info("UPDATE packet");
				if (hip_state.is_i1_sent() 
					or hip_state.is_unassociated() 
					or hip_state.is_i2_sent() 
					or hip_state.is_closing()
					or hip_state.is_closed()):
					logging.debug("Dropping the packet");
					continue;
				# Process the packet
				parameters       = hip_packet.get_parameters();

				# ACK 449
				# SEQ 385
				# HMAC 61505
				# Sign 61697

				ack_param        = None;
				seq_param        = None;
				signature_param  = None;
				mac_param        = None;
				dh_param         = None;
				esp_info         = None;
				
				if Utils.is_hit_smaller(rhit, ihit):
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				if Utils.is_hit_smaller(rhit, ihit):
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				if sv.is_responder:
					logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(ihit)))
					logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(rhit)))
					hmac_alg  = HIT.get_responders_oga_id(rhit);
					logging.debug("Responders's HMAC algorithm %d" % (hmac_alg))
				else:
					logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(rhit)))
					logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(ihit)))					
					hmac_alg  = HIT.get_responders_oga_id(ihit);
					logging.debug("Reponder's HMAC algorithm %d" % (hmac_alg))

				if Utils.is_hit_smaller(rhit, ihit):
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, ihit, rhit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				for parameter in parameters:
					if isinstance(parameter, HIP.AckParameter):
						logging.debug("Acknowledgement parameter");
						ack_param = parameter;
					if isinstance(parameter, HIP.SequenceParameter):
						logging.debug("Sequence parameter");
						seq_param = parameter;
					if isinstance(parameter, HIP.MACParameter):	
						logging.debug("MAC parameter");
						mac_param = parameter;
					if isinstance(parameter, HIP.SignatureParameter):
						logging.debug("Signature parameter");
						signature_param = parameter;
					if isinstance(parameter, HIP.DHParameter):
						logging.debug("DH parameter");
						dh_param = parameter;
					if isinstance(parameter, HIP.ESPInfoParameter):
						logging.debug("ESP info parameter");
						esp_info_param = parameter;

				if not mac_param:
					logging.debug("Missing MAC parameter");
					continue;

				if not signature_param:
					logging.debug("Missing signature parameter");
					continue;
				
				hip_update_packet = HIP.UpdatePacket();
				hip_update_packet.set_senders_hit(ihit);
				hip_update_packet.set_receivers_hit(rhit);
				hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_update_packet.set_version(HIP.HIP_VERSION);
				hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				# Compute HMAC here
				# ACK 449
				# SEQ 385
				# HMAC 61505
				# Sign 61697

				buf = [];
				if seq_param:
					buf += seq_param.get_byte_buffer();
				if ack_param:
					buf += ack_param.get_byte_buffer();

				original_length = hip_update_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_update_packet.set_length(int(packet_length / 8));
				buf = hip_update_packet.get_buffer() + buf;

				if list(hmac.digest(bytearray(buf))) != list(mac_param.get_hmac()):
					logging.critical("Invalid HMAC. Dropping the packet");
					continue;

				responders_public_key = pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
							Utils.ipv6_bytes_to_hex_formatted(rhit));
				
				if isinstance(responders_public_key, RSAPublicKey):
					signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSAPublicKey):
					signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSALowPublicKey):
					signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

				hip_update_packet = HIP.UpdatePacket();
				hip_update_packet.set_senders_hit(ihit);
				hip_update_packet.set_receivers_hit(rhit);
				hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_update_packet.set_version(HIP.HIP_VERSION);
				hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				buf = [];
				if seq_param:
					buf += seq_param.get_byte_buffer();
				if ack_param:
					buf += ack_param.get_byte_buffer();
				buf += mac_param.get_byte_buffer();

				original_length = hip_update_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_update_packet.set_length(int(packet_length / 8));
				buf = hip_update_packet.get_buffer() + buf;

				if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
					logging.critical("Invalid signature. Dropping the packet");
					continue;
				else:
					logging.debug("Signature is correct");

				if ack_param:
					logging.debug("This is a response to a UPDATE. Skipping pong...");
					continue;

				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, rhit, ihit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				hip_update_packet = HIP.UpdatePacket();
				hip_update_packet.set_senders_hit(rhit);
				hip_update_packet.set_receivers_hit(ihit);
				hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_update_packet.set_version(HIP.HIP_VERSION);
				hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				ack_param = HIP.AckParameter();
				ack_param.set_ids([seq_param.get_id()]);
				hip_update_packet.add_parameter(ack_param);

				mac_param = HIP.MACParameter();
				mac_param.set_hmac(hmac.digest(bytearray(hip_update_packet.get_buffer())));
				hip_update_packet.add_parameter(mac_param);

				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());

				signature = signature_alg.sign(bytearray(hip_update_packet.get_buffer()));

				signature_param = HIP.SignatureParameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_update_packet.add_parameter(signature_param);

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
				checksum = Utils.hip_ipv4_checksum(
					src, 
					dst, 
					HIP.HIP_PROTOCOL, 
					hip_update_packet.get_length() * 8 + 8, 
					hip_update_packet.get_buffer());
				hip_update_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_update_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(dst);
				src_str = Utils.ipv4_bytes_to_string(src);
				
				logging.debug("Sending UPDATE ACK packet %s" % (dst_str));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str.strip(), 0));

				if hip_state.is_r2_sent():
					hip_state.established();
			elif hip_packet.get_packet_type() == HIP.HIP_NOTIFY_PACKET:
				logging.info("NOTIFY packet");
				if hip_state.is_i1_sent() or hip_state.is_i2_sent() or hip_state.is_unassociated():
					logging.debug("Dropping the packet...")
					continue;
				# process the packet...
			elif hip_packet.get_packet_type() == HIP.HIP_CLOSE_PACKET:
				logging.info("CLOSE packet");
				if hip_state.is_i1_sent() or hip_state.is_unassociated():
					logging.debug("Dropping the packet...");
				# send close ack packet
				parameters       = hip_packet.get_parameters();

				echo_param       = None;
				signature_param  = None;
				mac_param        = None;
				
				if Utils.is_hit_smaller(rhit, ihit):
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				if Utils.is_hit_smaller(rhit, ihit):
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				if not sv:
					logging.debug("Not state exists. Skipping the packet...")
					continue;

				if sv.is_responder:
					hmac_alg  = HIT.get_responders_oga_id(rhit);
					logging.debug("Responder's HMAC algorithm %d" % (hmac_alg));
				else:
					hmac_alg  = HIT.get_responders_oga_id(ihit);
					logging.debug("Responder's HMAC algorithm %d" % (hmac_alg));

				if Utils.is_hit_smaller(rhit, ihit):
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
						Utils.ipv6_bytes_to_hex_formatted(rhit));

				logging.debug("Cipher algorithm %d " % (cipher_alg));
				logging.debug("HMAC algorithm %d" % (hmac_alg));

				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, ihit, rhit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				for parameter in parameters:
					if isinstance(parameter, HIP.EchoRequestSignedParameter):
						logging.debug("Echo request signed parameter");
						echo_param = parameter;
						logging.debug(list(echo_param.get_byte_buffer()));
					if isinstance(parameter, HIP.MACParameter):	
						logging.debug("MAC parameter");
						mac_param = parameter;
					if isinstance(parameter, HIP.SignatureParameter):
						logging.debug("Signature parameter");
						signature_param = parameter;

				if not mac_param:
					logging.debug("Missing MAC parameter");
					continue;

				if not signature_param:
					logging.debug("Missing signature parameter");
					continue;
				
				hip_close_packet = HIP.ClosePacket();
				logging.debug("Sender's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(ihit)));
				logging.debug("Receiver's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(rhit)));
				hip_close_packet.set_senders_hit(ihit);
				hip_close_packet.set_receivers_hit(rhit);
				hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_close_packet.set_version(HIP.HIP_VERSION);
				hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				# Compute HMAC here
				# ECHO 897
				buf = [];
				buf += echo_param.get_byte_buffer();

				original_length = hip_close_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_close_packet.set_length(int(packet_length / 8));
				buf = hip_close_packet.get_buffer() + buf;

				logging.debug("------------------------------------");
				logging.debug(list((buf)));
				logging.debug("------------------------------------");

				if list(hmac.digest(bytearray(buf))) != list(mac_param.get_hmac()):
					logging.critical("Invalid HMAC. Dropping the packet");
					continue;
				logging.debug("HMAC OK");

				responders_public_key = pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
							Utils.ipv6_bytes_to_hex_formatted(rhit));

				if isinstance(responders_public_key, RSAPublicKey):
					signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSAPublicKey):
					signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
				elif isinstance(responders_public_key, ECDSALowPublicKey):
					signature_alg = ECDSASHA1Signature(responders_public_key.get_key_info());

				hip_close_packet = HIP.ClosePacket();
				hip_close_packet.set_senders_hit(ihit);
				hip_close_packet.set_receivers_hit(rhit);
				hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_close_packet.set_version(HIP.HIP_VERSION);
				hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				buf = [];
				buf += echo_param.get_byte_buffer();
				buf += mac_param.get_byte_buffer();

				original_length = hip_close_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_close_packet.set_length(int(packet_length / 8));
				buf = hip_close_packet.get_buffer() + buf;

				if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
					logging.critical("Invalid signature. Dropping the packet");
					continue;
				else:
					logging.debug("Signature is correct");

				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, rhit, ihit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				hip_close_ack_packet = HIP.CloseAckPacket();
				hip_close_ack_packet.set_senders_hit(rhit);
				hip_close_ack_packet.set_receivers_hit(ihit);
				hip_close_ack_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_close_ack_packet.set_version(HIP.HIP_VERSION);
				hip_close_ack_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				echo_response_param = HIP.EchoResponseSignedParameter();
				echo_response_param.add_opaque_data(echo_param.get_opaque_data());
				hip_close_ack_packet.add_parameter(echo_response_param);

				mac_param = HIP.MACParameter();
				mac_param.set_hmac(hmac.digest(bytearray(hip_close_ack_packet.get_buffer())));
				hip_close_ack_packet.add_parameter(mac_param);

				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());

				signature = signature_alg.sign(bytearray(hip_close_ack_packet.get_buffer()));

				signature_param = HIP.SignatureParameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_close_ack_packet.add_parameter(signature_param);

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
				checksum = Utils.hip_ipv4_checksum(
					src, 
					dst, 
					HIP.HIP_PROTOCOL, 
					hip_close_ack_packet.get_length() * 8 + 8, 
					hip_close_ack_packet.get_buffer());
				hip_close_ack_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_close_ack_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(dst);
				src_str = Utils.ipv4_bytes_to_string(src);
				
				logging.debug("Sending CLOSE ACK packet %s" % (dst_str));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str.strip(), 0));
				if hip_state.is_r2_sent() or hip_state.is_established() or hip_state.is_i2_sent() or hip_state.is_closing():
					hip_state.closed();
					if Utils.is_hit_smaller(rhit, ihit):
						sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
							Utils.ipv6_bytes_to_hex_formatted(ihit))
					else:
						sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
							Utils.ipv6_bytes_to_hex_formatted(rhit))
					sv.closed_timeout = time.time() + config.config["general"]["UAL"] + 2*config.config["general"]["MSL"];
			elif hip_packet.get_packet_type == HIP.HIP_CLOSE_ACK_PACKET:
				logging.info("CLOSE ACK packet");
				if hip_state.is_r2_sent() or hip_state.is_established() or hip_state.is_i1_sent() or hip_state.is_i2_sent() or hip_state.is_unassociated():
					logging.debug("Dropping packet");
					continue;
				if hip_state.is_closing() or hip_state.is_closed():
					logging.debug("Moving to unassociated state...");
					hip_state.unassociated();
		except Exception as e:
			# We need more inteligent handling of exceptions here
			logging.critical("Exception occured. Dropping packet HIPv2.")
			logging.critical(e);
			traceback.print_exc()

def ip_sec_loop():
	"""
	This loop is responsible for reading IPSec packets
	from the raw socket
	"""
	logging.info("Starting the IPSec loop");

	while True:
		try:
			buf           = bytearray(ip_sec_socket.recv(2*MTU));
			ipv4_packet   = IPv4.IPv4Packet(buf);

			data          = list(ipv4_packet.get_payload());
			ip_sec_packet = IPSec.IPSecPacket(data);

			# IPv4 fields
			src           = ipv4_packet.get_source_address();
			dst           = ipv4_packet.get_destination_address();

			src_str       = Utils.ipv4_bytes_to_string(src);
			dst_str       = Utils.ipv4_bytes_to_string(dst);

			#logging.debug("Got packet from %s to %s of %d bytes" % (src_str, dst_str, len(buf)));
			# Get SA record and construct the ESP payload
			sa_record   = ip_sec_sa.get_record(src_str, dst_str);
			hmac_alg    = sa_record.get_hmac_alg();
			cipher      = sa_record.get_aes_alg();
			hmac_key    = sa_record.get_hmac_key();
			cipher_key  = sa_record.get_aes_key();
			ihit        = sa_record.get_src();
			rhit        = sa_record.get_dst();

			if Utils.is_hit_smaller(rhit, ihit):
				sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
					Utils.ipv6_bytes_to_hex_formatted(ihit));
			else:
				sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
					Utils.ipv6_bytes_to_hex_formatted(rhit));

			sv.data_timeout = time.time() + config.config["general"]["UAL"];

			#logging.debug("HMAC key");
			#logging.debug(hmac_key);
			#logging.debug("Cipher key");
			#logging.debug(cipher_key);

			icv         = list(ip_sec_packet.get_byte_buffer())[-hmac_alg.LENGTH:];

			#logging.debug("Calculating ICV over IPSec packet");
			#logging.debug(list(ip_sec_packet.get_byte_buffer())[:-hmac_alg.LENGTH]);
				
			if bytearray(icv) != hmac_alg.digest(bytearray(list(ip_sec_packet.get_byte_buffer())[:-hmac_alg.LENGTH])):
				logging.critical("Invalid ICV in IPSec packet");
				continue;

			padded_data = list(ip_sec_packet.get_payload())[:-hmac_alg.LENGTH];
			#logging.debug("Encrypted padded data");
			#logging.debug(padded_data);

			iv          = padded_data[:cipher.BLOCK_SIZE];
			
			#logging.debug("IV");
			#logging.debug(iv);

			padded_data = padded_data[cipher.BLOCK_SIZE:];

			#logging.debug("Padded data");
			#logging.debug(padded_data);

			decrypted_data = cipher.decrypt(cipher_key, bytearray(iv), bytearray(padded_data));

			#logging.debug("Decrypted padded data");
			#logging.debug(decrypted_data);

			unpadded_data  = IPSec.IPSecUtils.unpad(cipher.BLOCK_SIZE, decrypted_data);
			next_header    = IPSec.IPSecUtils.get_next_header(decrypted_data);
			
			# Send IPv6 packet to destination
			ipv6_packet = IPv6.IPv6Packet();
			ipv6_packet.set_version(IPv6.IPV6_VERSION);
			ipv6_packet.set_destination_address(ihit);
			ipv6_packet.set_source_address(rhit);
			ipv6_packet.set_next_header(next_header);
			ipv6_packet.set_hop_limit(1);
			ipv6_packet.set_payload_length(len(unpadded_data));
			ipv6_packet.set_payload(unpadded_data);

			if Utils.is_hit_smaller(rhit, ihit):
				hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
					Utils.ipv6_bytes_to_hex_formatted(ihit));
			else:
				hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit));
			

			hip_state.established();

			#logging.debug("Sending IPv6 packet to %s" % (Utils.ipv6_bytes_to_hex_formatted(ihit)));
			hip_tun.write(bytearray(ipv6_packet.get_buffer()));
		except Exception as e:
			logging.critical("Exception occured. Dropping IPSec packet.");
			logging.critical(e);
			traceback.print_exc();

def tun_if_loop():
	"""
	This loop is responsible for reading the packets 
	from the TUN interface
	"""
	logging.info("Starting the TUN interface loop");
	while True:
		try:
			buf = hip_tun.read(MTU);
			#logging.info("Got packet on TUN interface %s bytes" % (len(buf)));
			packet = IPv6.IPv6Packet(buf);
			ihit = packet.get_source_address();
			rhit = packet.get_destination_address();
			logging.info("Source %s " % Utils.ipv6_bytes_to_hex_formatted(ihit));
			logging.info("Destination %s " % Utils.ipv6_bytes_to_hex_formatted(rhit));
			logging.info("Version %s " % (packet.get_version()));
			logging.info("Traffic class %s " % (packet.get_traffic_class()));
			logging.info("Flow label %s " % (packet.get_flow_label()));
			logging.info("Packet length %s " %(packet.get_payload_length()));
			logging.info("Next header %s " % (packet.get_next_header()));
			logging.info("Hop limit %s" % (packet.get_hop_limit()));
			# Get the state
			if Utils.is_hit_smaller(rhit, ihit):
				hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(rhit), 
					Utils.ipv6_bytes_to_hex_formatted(ihit));
			else:
				hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(ihit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit));
			if hip_state.is_unassociated() or hip_state.is_closing() or hip_state.is_closed():
				logging.debug("Unassociate state reached");
				logging.debug("Starting HIP BEX %f" % (time.time()));
				logging.info("Resolving %s to IPv4 address" % Utils.ipv6_bytes_to_hex_formatted(rhit));

				# Resolve the HIT code can be improved
				if not hit_resolver.resolve(Utils.ipv6_bytes_to_hex_formatted(rhit)):
					logging.critical("Cannot resolve HIT to IPv4 address");
					continue;

				# Convert bytes to string representation of IPv6 address
				dst_str = hit_resolver.resolve(
					Utils.ipv6_bytes_to_hex_formatted(rhit));
				dst = Math.int_to_bytes(
					Utils.ipv4_to_int(dst_str));
				src = Math.int_to_bytes(
					Utils.ipv4_to_int(
						routing.Routing.get_default_IPv4_address()));

				st = time.time();
				# Construct the DH groups parameter
				dh_groups_param = HIP.DHGroupListParameter();
				dh_groups_param.add_groups(config.config["security"]["supported_DH_groups"]);

				# Create I1 packet
				hip_i1_packet = HIP.I1Packet();
				hip_i1_packet.set_senders_hit(ihit);
				hip_i1_packet.set_receivers_hit(rhit);
				hip_i1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i1_packet.set_version(HIP.HIP_VERSION);
				hip_i1_packet.add_parameter(dh_groups_param);

				# Compute the checksum of HIP packet
				checksum = Utils.hip_ipv4_checksum(
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
				logging.debug("Sending I1 packet to %s %f" % (dst_str, time.time() - st));
				hip_socket.sendto(bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0));

				# Transition to an I1-Sent state
				hip_state.i1_sent();

				if Utils.is_hit_smaller(rhit, ihit):
					state_variables.save(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit),
						HIPState.StateVariables(hip_state.get_state(), ihit, rhit, src, dst));
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit))
				else:
					state_variables.save(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit),
						HIPState.StateVariables(hip_state.get_state(), ihit, rhit, src, dst));
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit))
				#sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
				#	Utils.ipv6_bytes_to_hex_formatted(ihit))
				
				sv.is_responder = False;

				sv.i1_timeout = time.time() + config.config["general"]["i1_timeout_s"];
				sv.i1_retries += 1;

			elif hip_state.is_established():
				#logging.debug("Sending IPSEC packet...")
				# IPv6 fields
				rhit_str    = Utils.ipv6_bytes_to_hex_formatted(rhit);
				ihit_str    = Utils.ipv6_bytes_to_hex_formatted(ihit);
				next_header = packet.get_next_header();
				data        = list(packet.get_payload());

				if Utils.is_hit_smaller(rhit, ihit):
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(rhit),
						Utils.ipv6_bytes_to_hex_formatted(ihit));
				else:
					sv = state_variables.get(Utils.ipv6_bytes_to_hex_formatted(ihit),
						Utils.ipv6_bytes_to_hex_formatted(rhit));
				sv.data_timeout = time.time() + config.config["general"]["UAL"];

				# Get SA record and construct the ESP payload
				sa_record  = ip_sec_sa.get_record(ihit_str, rhit_str);
				seq        = sa_record.get_sequence();
				spi        = sa_record.get_spi();
				hmac_alg   = sa_record.get_hmac_alg();
				cipher     = sa_record.get_aes_alg();
				hmac_key   = sa_record.get_hmac_key();
				cipher_key = sa_record.get_aes_key();
				src        = sa_record.get_src();
				dst        = sa_record.get_dst();
				iv         = list(Utils.generate_random(cipher.BLOCK_SIZE));
				sa_record.increment_sequence();

				logging.debug("HMAC key");
				logging.debug(hmac_key);
				logging.debug("Cipher key");
				logging.debug(cipher_key);
			
				logging.debug("IV");
				logging.debug(iv);

				padded_data = IPSec.IPSecUtils.pad(cipher.BLOCK_SIZE, data, next_header);
				logging.debug("Length of the padded data %d" % (len(padded_data)));

				encrypted_data = cipher.encrypt(cipher_key, bytearray(iv), bytearray(padded_data));
				
				logging.debug("Padded data");
				logging.debug(iv + list(encrypted_data));
				logging.debug(list(encrypted_data));

				logging.debug("Encrypted padded data");
				logging.debug(padded_data);

				ip_sec_packet = IPSec.IPSecPacket();
				ip_sec_packet.set_spi(spi);
				ip_sec_packet.set_sequence(seq);
				ip_sec_packet.add_payload(iv + list(encrypted_data));

				logging.debug("Calculating ICV over IPSec packet");
				logging.debug(list(ip_sec_packet.get_byte_buffer()));

				icv = hmac_alg.digest(bytearray(ip_sec_packet.get_byte_buffer()));
				ip_sec_packet.add_payload(list(icv));

				# Send ESP packet to destination
				ipv4_packet = IPv4.IPv4Packet();
				ipv4_packet.set_version(IPv4.IPV4_VERSION);
				ipv4_packet.set_destination_address(dst);
				ipv4_packet.set_source_address(src);
				ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
				ipv4_packet.set_protocol(IPSec.IPSEC_PROTOCOL);
				ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
				ipv4_packet.set_payload(ip_sec_packet.get_byte_buffer());

				logging.debug("Sending IPSEC packet to %s %d bytes" % (Utils.ipv4_bytes_to_string(dst), len(ipv4_packet.get_buffer())));

				ip_sec_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(Utils.ipv4_bytes_to_string(dst), 0));
			else:
				logging.debug("Unknown state reached....");
		except Exception as e:
			logging.critical("Exception occured while processing packet from TUN interface. Dropping the packet.");
			logging.critical(e);
			traceback.print_exc()

hip_th_loop = threading.Thread(target = hip_loop, args = (), daemon = True);
ip_sec_th_loop = threading.Thread(target = ip_sec_loop, args = (), daemon = True);
tun_if_th_loop = threading.Thread(target = tun_if_loop, args = (), daemon = True);

logging.info("Starting the CuteHIP");

hip_th_loop.start();
ip_sec_th_loop.start();
tun_if_th_loop.start();

def exit_handler():

	for key in state_variables.keys():
		logging.debug("Sending close packet....");

		sv = state_variables.get_by_key(key);

		if Utils.is_hit_smaller(sv.rhit, sv.ihit):
			hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
		else:
			hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

		if hip_state.is_unassociated():
			continue;

		if Utils.is_hit_smaller(sv.rhit, sv.ihit):
			keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
		else:
			keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

		logging.debug("Responder's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
		logging.debug("Initiator's HIT %s" % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
		hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
		logging.debug("Responder's HMAC algorithm %d " % (hmac_alg))
		#if sv.is_responder:
		#	logging.debug("Host is Responder....")
		#	
		#	logging.debug("Responder's HMAC algorithm %d " % (hmac_alg))
		#else:
		#	hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
		#	logging.debug("Responder's HMAC algorithm %d " % (hmac_alg))

		if Utils.is_hit_smaller(sv.rhit, sv.ihit):
			#hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
			cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
		else:
			#hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
			cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

		if sv.is_responder:
			(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
		else:
			(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
		hmac = HMACFactory.get(hmac_alg, hmac_key);

		hip_close_packet = HIP.ClosePacket();

		if sv.is_responder:
			hip_close_packet.set_senders_hit(sv.rhit);
			hip_close_packet.set_receivers_hit(sv.ihit);
		else:
			hip_close_packet.set_senders_hit(sv.ihit);
			hip_close_packet.set_receivers_hit(sv.rhit);

		hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
		hip_close_packet.set_version(HIP.HIP_VERSION);
		hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

		echo_param = HIP.EchoRequestSignedParameter();
		echo_param.add_opaque_data(list(Utils.generate_random(4)));
		hip_close_packet.add_parameter(echo_param);

		mac_param = HIP.MACParameter();
		mac_param.set_hmac(hmac.digest(bytearray(hip_close_packet.get_buffer())));
		hip_close_packet.add_parameter(mac_param);

		#signature_alg = RSASHA256Signature(privkey.get_key_info());
		if isinstance(privkey, RSAPrivateKey):
			signature_alg = RSASHA256Signature(privkey.get_key_info());
		elif isinstance(privkey, ECDSAPrivateKey):
			signature_alg = ECDSASHA384Signature(privkey.get_key_info());
		elif isinstance(privkey, ECDSALowPrivateKey):
			signature_alg = ECDSASHA1Signature(privkey.get_key_info());
		
		signature = signature_alg.sign(bytearray(hip_close_packet.get_buffer()));

		signature_param = HIP.SignatureParameter();
		signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
		signature_param.set_signature(signature);

		hip_close_packet.add_parameter(signature_param);

		# Create IPv4 packet
		ipv4_packet = IPv4.IPv4Packet();
		ipv4_packet.set_version(IPv4.IPV4_VERSION);
		ipv4_packet.set_destination_address(sv.dst);
		ipv4_packet.set_source_address(sv.src);
		ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
		ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
		ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

		# Calculate the checksum
		checksum = Utils.hip_ipv4_checksum(
			sv.dst, 
			sv.src, 
			HIP.HIP_PROTOCOL, 
			hip_close_packet.get_length() * 8 + 8, 
			hip_close_packet.get_buffer());
		hip_close_packet.set_checksum(checksum);
		ipv4_packet.set_payload(hip_close_packet.get_buffer());
		# Send the packet
		dst_str = Utils.ipv4_bytes_to_string(sv.dst);
		src_str = Utils.ipv4_bytes_to_string(sv.src);
				
		logging.debug("Sending CLOSE PACKET packet %s" % (dst_str));
		hip_socket.sendto(
			bytearray(ipv4_packet.get_buffer()), 
			(dst_str, 0));

	routing.Routing.del_hip_default_route();
	main_loop = False;

atexit.register(exit_handler);

main_loop = True;

while main_loop:
	#logging.debug("Periodic tasks")
	time.sleep(1);
	for key in state_variables.keys():
		#logging.debug("Periodic task for %s" % (key));
		sv = state_variables.get_by_key(key);
		if Utils.is_hit_smaller(sv.rhit, sv.ihit):
			hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
		else:
			hip_state = hip_state_machine.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
				Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
		if hip_state.is_established():
			if time.time() >= sv.data_timeout:

				if Utils.is_hit_smaller(sv.rhit, sv.ihit):
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
				else:
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

				#if sv.is_responder:
				#	logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
				#	logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
				#	hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
				#	logging.debug("Using Responder's HMAC algorithm %d" % (hmac_alg))
				#else:
				logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
				logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
				hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
				logging.debug("Responders's HMAC algorithm %d" % (hmac_alg))
				
				if Utils.is_hit_smaller(sv.rhit, sv.ihit):
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
					#hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
				else:
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
					#hmac_alg  = HIT.get_responders_oga_id(sv.rhit);

				#(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
				if sv.is_responder:
					(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
				else:
					(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);

				hmac = HMACFactory.get(hmac_alg, hmac_key);
				logging.debug("HMAC algorithm %d" % (hmac_alg));
				logging.debug(list(hmac_key));

				hip_close_packet = HIP.ClosePacket();
				if sv.is_responder:
					hip_close_packet.set_senders_hit(sv.rhit);
					hip_close_packet.set_receivers_hit(sv.ihit);
				else:
					hip_close_packet.set_senders_hit(sv.ihit);
					hip_close_packet.set_receivers_hit(sv.rhit);
				hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_close_packet.set_version(HIP.HIP_VERSION);
				hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				echo_param = HIP.EchoRequestSignedParameter();
				echo_param.add_opaque_data(list(Utils.generate_random(4)));
				hip_close_packet.add_parameter(echo_param);

				mac_param = HIP.MACParameter();
				logging.debug("------------------------------");
				logging.debug(list(hip_close_packet.get_buffer()));
				logging.debug("------------------------------");
				mac_param.set_hmac(hmac.digest(bytearray(hip_close_packet.get_buffer())));
				hip_close_packet.add_parameter(mac_param);

				#signature_alg = RSASHA256Signature(privkey.get_key_info());
				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());
				
				signature = signature_alg.sign(bytearray(hip_close_packet.get_buffer()));

				signature_param = HIP.SignatureParameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_close_packet.add_parameter(signature_param);

				# Create IPv4 packet
				ipv4_packet = IPv4.IPv4Packet();
				ipv4_packet.set_version(IPv4.IPV4_VERSION);
				ipv4_packet.set_destination_address(sv.dst);
				ipv4_packet.set_source_address(sv.src);
				ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
				ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
				ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

				# Calculate the checksum
				checksum = Utils.hip_ipv4_checksum(
					sv.dst, 
					sv.src, 
					HIP.HIP_PROTOCOL, 
					hip_close_packet.get_length() * 8 + 8, 
					hip_close_packet.get_buffer());
				hip_close_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_close_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(sv.dst);
				src_str = Utils.ipv4_bytes_to_string(sv.src);
						
				logging.debug("Sending CLOSE PACKET packet %s" % (dst_str));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str, 0));

				hip_state.closing();

				sv.closing_timeout = time.time() + config.config["general"]["UAL"] + config.config["general"]["MSL"];

				continue;

			if time.time() >= sv.update_timeout:
				sv.update_timeout = time.time() + config.config["general"]["update_timeout_s"];
				if Utils.is_hit_smaller(sv.rhit, sv.ihit):
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
				else:
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.rhit));
				
				#if sv.is_responder:
				#	logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
				#	logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
				#	hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
				#	logging.debug("Using Responder's HMAC algorithm %d" % (hmac_alg))
				#else:
				logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
				logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
				hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
				logging.debug("Using Responders's HMAC algorithm %d" % (hmac_alg))

				if Utils.is_hit_smaller(sv.rhit, sv.ihit):
					#hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
				else:
					#hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

				if sv.is_responder:
					(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
				else:
					(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				hip_update_packet = HIP.UpdatePacket();
				if sv.is_responder:
					hip_update_packet.set_senders_hit(sv.rhit);
					hip_update_packet.set_receivers_hit(sv.ihit);
					logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
					logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
				else:
					hip_update_packet.set_senders_hit(sv.ihit);
					hip_update_packet.set_receivers_hit(sv.rhit);
					logging.debug("Source HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
					logging.debug("Destination HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
				hip_update_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_update_packet.set_version(HIP.HIP_VERSION);
				hip_update_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				sv.update_seq += 1;
				seq_param = HIP.SequenceParameter();
				seq_param.set_id(sv.update_seq);
				hip_update_packet.add_parameter(seq_param);

				mac_param = HIP.MACParameter();
				mac_param.set_hmac(hmac.digest(bytearray(hip_update_packet.get_buffer())));
				hip_update_packet.add_parameter(mac_param);

				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());
				signature = signature_alg.sign(bytearray(hip_update_packet.get_buffer()));

				signature_param = HIP.SignatureParameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_update_packet.add_parameter(signature_param);

				# Create IPv4 packet
				ipv4_packet = IPv4.IPv4Packet();
				ipv4_packet.set_version(IPv4.IPV4_VERSION);
				ipv4_packet.set_destination_address(sv.dst);
				ipv4_packet.set_source_address(sv.src);
				ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
				ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
				ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

				# Calculate the checksum
				checksum = Utils.hip_ipv4_checksum(
					sv.dst, 
					sv.src, 
					HIP.HIP_PROTOCOL, 
					hip_update_packet.get_length() * 8 + 8, 
					hip_update_packet.get_buffer());
				hip_update_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_update_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(sv.dst);
				src_str = Utils.ipv4_bytes_to_string(sv.src);
				
				logging.debug("Sending UPDATE PACKET packet %s" % (dst_str));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str, 0));
		elif hip_state.is_i1_sent():
			if time.time() >= sv.i1_timeout:
				sv.i1_timeout = time.time() + config.config["general"]["i1_timeout_s"];
				dh_groups_param = HIP.DHGroupListParameter();
				dh_groups_param.add_groups(config.config["security"]["supported_DH_groups"]);

				# Create I1 packet
				hip_i1_packet = HIP.I1Packet();
				hip_i1_packet.set_senders_hit(sv.ihit);
				hip_i1_packet.set_receivers_hit(sv.rhit);
				hip_i1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i1_packet.set_version(HIP.HIP_VERSION);
				hip_i1_packet.add_parameter(dh_groups_param);

				# Compute the checksum of HIP packet
				checksum = Utils.hip_ipv4_checksum(
					sv.src, 
					sv.dst, 
					HIP.HIP_PROTOCOL, 
					hip_i1_packet.get_length() * 8 + 8, 
					hip_i1_packet.get_buffer());
				hip_i1_packet.set_checksum(checksum);

				dst_str = Utils.ipv4_bytes_to_string(sv.dst);
				src_str = Utils.ipv4_bytes_to_string(sv.src);

				# Construct the IPv4 packet
				ipv4_packet = IPv4.IPv4Packet();
				ipv4_packet.set_version(IPv4.IPV4_VERSION);
				ipv4_packet.set_destination_address(sv.dst);
				ipv4_packet.set_source_address(sv.src);
				ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
				ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
				ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);
				ipv4_packet.set_payload(hip_i1_packet.get_buffer());

				# Send HIP I1 packet to destination
				logging.debug("Sending I1 packet to %s" % (dst_str));
				hip_socket.sendto(bytearray(ipv4_packet.get_buffer()), (dst_str.strip(), 0))

				sv.i1_retries += 1;
				if sv.i1_retries > config.config["general"]["i1_retries"]:
					hip_state.failed();
					sv.failed_timeout = time.time() + config.config["general"]["failed_timeout"];
		elif hip_state.is_i2_sent():
			if sv.i2_timeout <= time.time():
				dst_str = Utils.ipv4_bytes_to_string(sv.dst);
				# Send HIP I2 packet to destination
				logging.debug("Sending I2 packet to %s" % (dst_str));
				hip_socket.sendto(bytearray(sv.i2_packet.get_buffer()), (dst_str.strip(), 0))
				sv.i2_retries += 1;
				if sv.i2_retries > config.config["general"]["i2_retries"]:
					hip_state.failed();
					sv.failed_timeout = time.time() + config.config["general"]["failed_timeout"];
					continue;
				sv.i2_timeout = time.time() + config.config["general"]["i2_timeout_s"];
		elif hip_state.is_r2_sent():
			if sv.ec_complete_timeout <= time.time():
				logging.debug("EC timeout. Moving to established state...");
				hip_state.established();
		elif hip_state.is_closing():
			if sv.closing_timeout <= time.time():
				if Utils.is_hit_smaller(sv.rhit, sv.ihit):
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
				else:
					keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

				#if sv.is_responder:
				#	logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
				#	logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
				#	hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
				#	logging.debug("Using Responder's HMAC algorithm %d" % (hmac_alg))
				#else:
				logging.debug("Reponder's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.rhit)))
				logging.debug("Initiator's HIT %s " % (Utils.ipv6_bytes_to_hex_formatted(sv.ihit)))
				hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
				logging.debug("Responders's HMAC algorithm %d" % (hmac_alg))

				if Utils.is_hit_smaller(sv.rhit, sv.ihit):
					#hmac_alg  = HIT.get_responders_oga_id(sv.ihit);
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.rhit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.ihit));
				else:
					#hmac_alg  = HIT.get_responders_oga_id(sv.rhit);
					cipher_alg = cipher_storage.get(Utils.ipv6_bytes_to_hex_formatted(sv.ihit), 
						Utils.ipv6_bytes_to_hex_formatted(sv.rhit));

				if sv.is_responder:
					(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.rhit, sv.ihit);
				else:
					(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, cipher_alg, sv.ihit, sv.rhit);

				logging.debug("HMAC algorithm %d" % (hmac_alg));
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				hip_close_packet = HIP.ClosePacket();
				hip_close_packet.set_senders_hit(sv.ihit);
				hip_close_packet.set_receivers_hit(sv.rhit);
				hip_close_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_close_packet.set_version(HIP.HIP_VERSION);
				hip_close_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				echo_param = HIP.EchoRequestSignedParameter();
				echo_param.add_opaque_data(list(Utils.generate_random(4)));
				hip_close_packet.add_parameter(echo_param);

				mac_param = HIP.MACParameter();
				mac_param.set_hmac(hmac.digest(bytearray(hip_close_packet.get_buffer())));
				hip_close_packet.add_parameter(mac_param);

				#signature_alg = RSASHA256Signature(privkey.get_key_info());
				if isinstance(privkey, RSAPrivateKey):
					signature_alg = RSASHA256Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSAPrivateKey):
					signature_alg = ECDSASHA384Signature(privkey.get_key_info());
				elif isinstance(privkey, ECDSALowPrivateKey):
					signature_alg = ECDSASHA1Signature(privkey.get_key_info());
				
				signature = signature_alg.sign(bytearray(hip_close_packet.get_buffer()));

				signature_param = HIP.SignatureParameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_close_packet.add_parameter(signature_param);

				# Create IPv4 packet
				ipv4_packet = IPv4.IPv4Packet();
				ipv4_packet.set_version(IPv4.IPV4_VERSION);
				ipv4_packet.set_destination_address(sv.dst);
				ipv4_packet.set_source_address(sv.src);
				ipv4_packet.set_ttl(IPv4.IPV4_DEFAULT_TTL);
				ipv4_packet.set_protocol(HIP.HIP_PROTOCOL);
				ipv4_packet.set_ihl(IPv4.IPV4_IHL_NO_OPTIONS);

				# Calculate the checksum
				checksum = Utils.hip_ipv4_checksum(
					sv.dst, 
					sv.src, 
					HIP.HIP_PROTOCOL, 
					hip_close_packet.get_length() * 8 + 8, 
					hip_close_packet.get_buffer());
				hip_close_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_close_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(sv.dst);
				src_str = Utils.ipv4_bytes_to_string(sv.src);
						
				logging.debug("Sending CLOSE PACKET packet %s" % (dst_str));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str.strip(), 0));
			else:
				logging.debug("Transitioning to UNASSOCIATED state....")
				hip_state.unassociated();
		elif hip_state.is_closed():
			if sv.closed_timeout <= time.time():
				logging.debug("Transitioning to UNASSOCIATED state....")
				hip_state.unassociated();
		elif hip_state.is_failed():
			if sv.failed_timeout <= time.time():
				logging.debug("Transitioning to UNASSOCIATED state...");
				hip_state.unassociated();
