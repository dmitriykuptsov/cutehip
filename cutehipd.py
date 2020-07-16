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
from utils.hi import RSAHostID, ECDSAHostID
from utils.di import DIFactory
# Utilities
from utils.misc import Utils, Math
# Puzzle solver
from utils.puzzles import PuzzleSolver
# Crypto
from crypto import factory
from crypto.asymmetric import RSAPublicKey, RSAPrivateKey, ECDSAPublicKey, ECDSAPrivateKey, RSASHA256Signature
from crypto.factory import HMACFactory, SymmetricCiphersFactory
# Tun interface
from network import tun
# Routing
from network import routing
# States
from databases import HIPState
from databases import SA
from databases import resolver
# Utilities
from utils.misc import Utils
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

#print(Utils.kdf(0x1, bytearray([1, 2, 3, 4, 5, 6, 7, 8]), bytearray([1, 2, 3, 4, 5, 6, 7, 8]), bytearray([1, 2, 3, 4, 5, 6, 7, 8]), 4))

MTU = config.config["network"]["mtu"];

# HIP v2 https://tools.ietf.org/html/rfc7401#section-3
logging.info("Using hosts file to resolve HITS %s" % (config.config["resolver"]["hosts_file"]));
hit_resolver = resolver.HostsFileResolver(filename = config.config["resolver"]["hosts_file"]);

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

logging.debug(di);

logging.info("Loading public key and constructing HIT")

pubkey = None;
privkey = None;
hi = None;

if config.config["security"]["sig_alg"] == 0x5: # RSA
	pubkey = RSAPublicKey.load_pem(config.config["security"]["public_key"]);
	privkey = RSAPrivateKey.load_pem(config.config["security"]["private_key"]);
	hi = RSAHostID(pubkey.get_public_exponent(), pubkey.get_modulus());
#elif config.config["security"]["sig_alg"] == 0x7: # ECDSA
#	pubkey = ECDSAPublicKey.load_pem(config.config["security"]["public_key"]);
#	privkey = ECDSAPrivateKey.load_pem(config.config["security"]["private_key"]);
#	hi = ECDSAHostID(pubkey.get_curve_id(), pubkey.get_x(), pubkey.get_y());
#elif config.config["security"]["sig_alg"] == 0x9: # ECDSA LOW
#	pubkey = ECDSALowPublicKey.load_pem(config.config["security"]["public_key"]);
#	privkey = ECDSALowPrivateKey.load_pem(config.config["security"]["private_key"]);
#	hi = ECDSALowHostID(pubkey.get_curve_id(), pubkey.get_x(), pubkey.get_y());
else:
	raise Exception("Unsupported Host ID algorithm")

logging.debug("Configuring TUN interface");
ipv6_address = HIT.get_hex_formated(hi.to_byte_array(), HIT.SHA256_OGA);
own_hit = HIT.get(hi.to_byte_array(), HIT.SHA256_OGA);
logging.info("Configuring TUN device");
hip_tun = tun.Tun(address=ipv6_address, mtu=MTU);
logging.info("Configuring IPv6 routes");
routing.Routing.add_hip_default_route();

logging.debug("Configuring state machine and storage");
hip_state_machine = HIPState.StateMachine();
keymat_storage = HIPState.Storage();
dh_storage = HIPState.Storage();
pubkey_storage = HIPState.Storage();

def hip_loop():
	"""
	This loop is responsible for reading HIP packets
	from the raw socket
	"""
	logging.info("Starting the HIP loop");

	while True:
		try:
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
			if not Utils.hits_equal(rhit, own_hit) and not Utils.hits_equal(rhit, [0] * 16):
				logging.critical("Not our HIT");
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

				st = time.time();
				
				# Check the state of the HIP protocol
				# R1 packet should be constructed only 
				# if the state is not associated
				# Need to check with the RFC

				# Construct R1 packet
				hip_r1_packet = HIP.R1Packet();
				hip_r1_packet.set_senders_hit(rhit);
				#hip_r1_packet.set_receivers_hit(shit);
				hip_r1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r1_packet.set_version(HIP.HIP_VERSION);

				r_hash = HIT.get_responders_hash_algorithm(rhit);

				# Prepare puzzle
				irandom = PuzzleSolver.generate_irandom(r_hash.LENGTH);
				puzzle_param = HIP.PuzzleParameter(buffer = None, rhash_length = r_hash.LENGTH);
				puzzle_param.set_k_value(config.config["security"]["puzzle_difficulty"]);
				puzzle_param.set_lifetime(config.config["security"]["puzzle_lifetime_exponent"]);
				puzzle_param.set_random([0] * r_hash.LENGTH);
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
				for group in supported_dh_groups:
					if group in offered_dh_groups:
						dh_groups_param.add_groups([group]);
						selected_dh_group = group;
						break;
				if not selected_dh_group:
					logging.debug("Unsupported DH group");
					continue;

				dh = factory.DHFactory.get(selected_dh_group);
				private_key = dh.generate_private_key();
				public_key = dh.generate_public_key();
				dh_storage.save(Utils.ipv6_bytes_to_hex_formatted(shit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit), dh);

				dh_param = HIP.DHParameter();
				dh_param.set_group_id(selected_dh_group);
				logging.debug("DH public key: %d ", Math.bytes_to_int(dh.encode_public_key()));
				dh_param.add_public_value(dh.encode_public_key());
				logging.debug("DH public key value: %d ", Math.bytes_to_int(dh.encode_public_key()));
				logging.debug("DH public key value: %d ", Math.bytes_to_int(dh_param.get_public_value()));

				# HIP cipher param
				cipher_param = HIP.CipherParameter();
				cipher_param.add_ciphers(config.config["security"]["supported_ciphers"]);

				# HIP host ID parameter
				hi_param = HIP.HostIdParameter();
				hi_param.set_host_id(hi);
				# It is important to set domain ID after host ID was set
				logging.debug(di);
				hi_param.set_domain_id(di);

				# HIP HIT suit list parameter
				hit_suit_param = HIP.HITSuitListParameter();
				hit_suit_param.add_suits(config.config["security"]["supported_hit_suits"]);

				# Transport format list
				transport_param = HIP.TransportListParameter();
				transport_param.add_transport_formats(config.config["security"]["supported_transports"]);

				# HIP signature parameter
				signature_param = HIP.Signature2Parameter();
				#

				# Compute signature here
				buf = puzzle_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer() + \
						hit_suit_param.get_byte_buffer() + \
						dh_groups_param.get_byte_buffer() + \
						transport_param.get_byte_buffer();
				original_length = hip_r1_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r1_packet.set_length(int(packet_length / 8));
				buf = hip_r1_packet.get_buffer() + buf;
				signature_alg = RSASHA256Signature(privkey.get_key_info());

				#logging.debug(privkey.get_key_info());
				signature = signature_alg.sign(bytearray(buf));
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				# Add parameters to R1 packet (order is important)
				hip_r1_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);
				# List of mandatory parameters in R1 packet...
				puzzle_param.set_random(irandom);
				puzzle_param.set_opaque(list(Utils.generate_random(2)));
				hip_r1_packet.add_parameter(puzzle_param);
				hip_r1_packet.add_parameter(dh_param);
				hip_r1_packet.add_parameter(cipher_param);
				hip_r1_packet.add_parameter(hi_param);
				hip_r1_packet.add_parameter(hit_suit_param);
				hip_r1_packet.add_parameter(dh_groups_param);
				hip_r1_packet.add_parameter(transport_param);
				hip_r1_packet.add_parameter(signature_param);

				# Swap the addresses
				temp = src;
				src = dst;
				dst = temp;

				# Set receiver's HIT
				hip_r1_packet.set_receivers_hit(shit);

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
				logging.debug("Sending R1 packet to %s %d" % (dst_str, (time.time() - st)));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str, 0));
			elif hip_packet.get_packet_type() == HIP.HIP_R1_PACKET:
				logging.info("R1 packet");
				puzzle_param     = None;
				r1_counter_param = None;
				irandom          = None;
				opaque           = None;
				dh_param         = None;
				cipher_param     = None;
				hi_param         = None;
				hit_suit_param   = None;
				dh_groups_param  = None;
				transport_param  = None;
				echo_signed      = None;
				signature_param  = None;
				public_key       = None;
				echo_unsigned    = [];
				parameters       = hip_packet.get_parameters();
				
				st = time.time();

				hip_r1_packet = HIP.R1Packet();
				hip_r1_packet.set_senders_hit(hip_packet.get_senders_hit());
				#hip_r1_packet.set_receivers_hit(shit);
				hip_r1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r1_packet.set_version(HIP.HIP_VERSION);

				r_hash = HIT.get_responders_hash_algorithm(rhit);

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
						irandom = puzzle_param.get_random();
						opaque = puzzle_param.get_opaque();
						puzzle_param.set_random([0] * r_hash.LENGTH);
						puzzle_param.set_opaque(list([0, 0]));
					if isinstance(parameter, HIP.DHParameter):	
						logging.debug("DH parameter");
						dh_param = parameter;
					if isinstance(parameter, HIP.HostIdParameter):
						logging.debug("DI type: %d " % parameter.get_di_type());
						logging.debug("DI value: %s " % parameter.get_domain_id());
						logging.debug("Host ID");
						hi_param = parameter;
						# Check the algorithm and construct the HI based on the proposed algorithm
						responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
						if hi_param.get_algorithm() != config.config["security"]["sig_alg"]:
							logging.critical("Invalid signature algorithm");
							continue;
						oga = HIT.get_responders_oga_id(rhit);
						responders_hit = HIT.get(responder_hi.to_byte_array(), oga);
						if not Utils.hits_equal(shit, responders_hit):
							logging.critical("Not our HIT");
							raise Exception("Invalid HIT");
						responders_public_key = RSAPublicKey.load_from_params(
							responder_hi.get_exponent(), 
							responder_hi.get_modulus());
						pubkey_storage.save(Utils.ipv6_bytes_to_hex_formatted(shit), 
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
						echo_signed = EchoResponseSignedParameter();
						echo_signed.add_opaque_data(parameter.get_opaque_data());
					if isinstance(parameter, HIP.EchoRequestUnsignedParameter):
						logging.debug("Echo request unsigned parameter");
						echo_unsigned_param = EchoResponseUnsignedParameter();
						echo_unsigned_param.add_opaque_data(parameter.get_opaque_data());
						echo_unsigned.append(echo_unsigned_param);
					if isinstance(parameter, HIP.CipherParameter):
						logging.debug("Ciphers");
						cipher_param = parameter;
				if not puzzle_param:
					logging.critical("Missing puzzle parameter");
					continue;
				if not dh_param:
					logging.critical("Missing DH parameter");
					continue;
				if not cipher_param:
					logging.critical("Missing cipher parameter");
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
				if (end_time - start_time) > 2**(puzzle_param.get_lifetime() - 32):
					logging.critical("Maximum time to solve the puzzle exceeded. Dropping the packet...");
					# Abandon the BEX

				buf = [];

				if r1_counter_param:
					buf += r1_counter_param.get_byte_buffer();

				if not echo_signed:
					buf += puzzle_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer() + \
						hit_suit_param.get_byte_buffer() + \
						dh_groups_param.get_byte_buffer() + \
						transport_param.get_byte_buffer();
				else:
					buf += puzzle_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer() + \
						hit_suit_param.get_byte_buffer() + \
						dh_groups_param.get_byte_buffer() + \
						echo_signed.get_byte_buffer() + \
						transport_param.get_byte_buffer();
				original_length = hip_r1_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r1_packet.set_length(int(packet_length / 8));
				buf = bytearray(hip_r1_packet.get_buffer()) + bytearray(buf);
				signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
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

				dh_storage.save(Utils.ipv6_bytes_to_hex_formatted(shit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit), dh);

				info = Utils.sort_hits(shit, rhit);
				salt = irandom + jrandom;
				hmac_alg  = HIT.get_responders_oga_id(rhit);

				offered_ciphers = cipher_param.get_ciphers();
				supported_ciphers = config.config["security"]["supported_ciphers"];
				selected_cipher = None;

				for cipher in supported_ciphers:
					if cipher in offered_ciphers:
						selected_cipher = cipher;
						break;

				if not selected_cipher:
					logging.critical("Unsupported cipher");
					# Transition to unassociated state
					raise Exception("Unsupported cipher");

				keymat_length_in_octets = Utils.compute_keymat_length(hmac_alg, selected_cipher);
				keymat = Utils.kdf(hmac_alg, salt, Math.int_to_bytes(shared_secret), info, keymat_length_in_octets);

				keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(shit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit), keymat);

				logging.debug("Processing R1 packet %d" % (time.time() - st));

				st = time.time();

				# Transition to I2 state
				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(rhit);
				hip_i2_packet.set_receivers_hit(shit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);

				solution_param = HIP.SolutionParameter(buffer = None, rhash_length = r_hash.LENGTH);
				solution_param.set_k_value(puzzle_param.get_k_value());
				solution_param.set_opaque(opaque);
				solution_param.set_random(irandom);
				solution_param.set_solution(jrandom);

				dh_param = HIP.DHParameter();
				dh_param.set_group_id(selected_dh_group);
				dh_param.add_public_value(dh.encode_public_key());

				cipher_param = HIP.CipherParameter();
				cipher_param.add_ciphers([selected_cipher]);

				hi_param = HIP.HostIdParameter();
				hi_param.set_host_id(hi);
				hi_param.set_domain_id(di);

				transport_param = HIP.TransportListParameter();
				transport_param.add_transport_formats(config.config["security"]["supported_transports"]);

				mac_param = HIP.MACParameter();

				# Compute HMAC here
				buf = [];
				if r1_counter_param:
					buf += r1_counter_param.get_byte_buffer();

				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed:
					buf += echo_signed.get_byte_buffer();

				buf += transport_param.get_byte_buffer();

				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = hip_i2_packet.get_buffer() + buf;
				
				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, shit, rhit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);
				mac_param.set_hmac(hmac.digest(bytearray(buf)));

				# Compute signature here
				
				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(rhit);
				hip_i2_packet.set_receivers_hit(shit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);
				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				buf = [];
				if r1_counter_param:
					buf += r1_counter_param.get_byte_buffer();

				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed:
					buf += echo_signed.get_byte_buffer();

				buf += transport_param.get_byte_buffer() + \
						mac_param.get_byte_buffer();
				
				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = hip_i2_packet.get_buffer() + buf;
				signature_alg = RSASHA256Signature(privkey.get_key_info());
				signature = signature_alg.sign(bytearray(buf));

				signature_param = HIP.SignatureParameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);
				if r1_counter_param:
					hip_i2_packet.add_parameter(r1_counter_param);
				hip_i2_packet.add_parameter(solution_param);
				hip_i2_packet.add_parameter(dh_param);
				hip_i2_packet.add_parameter(cipher_param);
				hip_i2_packet.add_parameter(hi_param);
				if echo_signed:
					hip_i2_packet.add_parameter(echo_signed);
				hip_i2_packet.add_parameter(transport_param);
				hip_i2_packet.add_parameter(mac_param);
				hip_i2_packet.add_parameter(signature_param);
				for unsigned_param in echo_unsigned:
					hip_i2_packet.add_parameter(unsigned_param);

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
					hip_i2_packet.get_length() * 8 + 8, 
					hip_i2_packet.get_buffer());
				hip_i2_packet.set_checksum(checksum);
				ipv4_packet.set_payload(hip_i2_packet.get_buffer());
				# Send the packet
				dst_str = Utils.ipv4_bytes_to_string(dst);
				logging.debug("Sending I2 packet to %s %d" % (dst_str, (time.time() - st)));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str, 0));

			elif hip_packet.get_packet_type() == HIP.HIP_I2_PACKET:
				logging.info("I2 packet");
				st = time.time();

				solution_param   = None;
				r1_counter_param = None;
				dh_param         = None;
				cipher_param     = None;
				hi_param         = None;
				transport_param  = None;
				mac_param        = None;
				signature_param  = None;
				echo_signed      = None;
				parameters       = hip_packet.get_parameters();
				for parameter in parameters:
					if isinstance(parameter, HIP.R1CounterParameter):
						logging.debug("R1 counter");
						r1_counter_param = parameter;
					if isinstance(parameter, HIP.SolutionParameter):
						logging.debug("Puzzle solution parameter");
						solution_param = parameter;
					if isinstance(parameter, HIP.DHParameter):	
						logging.debug("DH parameter");
						dh_param = parameter;
					if isinstance(parameter, HIP.HostIdParameter):
						logging.debug("Host ID");
						hi_param = parameter;
						responder_hi = RSAHostID.from_byte_buffer(hi_param.get_host_id());
						if hi_param.get_algorithm() != config.config["security"]["sig_alg"]:
							logging.critical("Invalid signature algorithm");
							continue;
						oga = HIT.get_responders_oga_id(rhit);
						responders_hit = HIT.get(responder_hi.to_byte_array(), oga);
						if not Utils.hits_equal(shit, responders_hit):
							logging.critical("Not our HIT");
							raise Exception("Invalid HIT");
						responders_public_key = RSAPublicKey.load_from_params(
							responder_hi.get_exponent(), 
							responder_hi.get_modulus());
					if isinstance(parameter, HIP.TransportListParameter):
						logging.debug("Transport parameter");
						transport_param = parameter;
					if isinstance(parameter, HIP.SignatureParameter):
						logging.debug("Signature parameter");
						signature_param = parameter;
					if isinstance(parameter, HIP.CipherParameter):
						logging.debug("Ciphers");
						cipher_param = parameter;
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
				
				oga = HIT.get_responders_oga_id(rhit);

				#if oga not in config.config["security"]["supported_hit_suits"]:
				#	logging.critical("Unsupported HIT suit");
				#	continue;
				jrandom = solution_param.get_solution();
				irandom = solution_param.get_random();
				if not PuzzleSolver.verify_puzzle(
					irandom, 
					jrandom, 
					hip_packet.get_senders_hit(), 
					hip_packet.get_receivers_hit(), 
					puzzle_param.get_k_value(), r_hash):
					logging.debug("Puzzle was not solved....");
					continue;
				logging.debug("Puzzle was solved");

				dh_storage.get(Utils.ipv6_bytes_to_hex_formatted(shit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit));

				public_key_r = dh.decode_public_key(dh_param.get_public_value());
				shared_secret = dh.compute_shared_secret(public_key_r);
				logging.debug("Secret key %d" % shared_secret);

				info = Utils.sort_hits(shit, rhit);
				salt = irandom + jrandom;
				hmac_alg  = HIT.get_responders_oga_id(rhit);

				offered_ciphers = cipher_param.get_ciphers();
				supported_ciphers = config.config["security"]["supported_ciphers"];
				selected_cipher = None;

				for cipher in supported_ciphers:
					if cipher in offered_ciphers:
						selected_cipher = cipher;
						break;

				if not selected_cipher:
					logging.critical("Unsupported cipher");
					# Transition to unassociated state
					raise Exception("Unsupported cipher");

				keymat_length_in_octets = Utils.compute_keymat_length(hmac_alg, selected_cipher);
				keymat = Utils.kdf(hmac_alg, salt, Math.int_to_bytes(shared_secret), info, keymat_length_in_octets);

				keymat_storage.save(Utils.ipv6_bytes_to_hex_formatted(shit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit), keymat);

				

				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(shit);
				hip_i2_packet.set_receivers_hit(rhit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);
				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				# Compute HMAC here
				buf = [];
				if r1_counter_param:
					buf += r1_counter_param.get_byte_buffer();

				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed:
					buf += echo_signed.get_byte_buffer();

				buf += transport_param.get_byte_buffer();

				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = hip_i2_packet.get_buffer() + buf;
				
				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, rhit, shit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);

				if list(hmac.digest(bytearray(buf))) != list(mac_param.get_hmac()):
					logging.critical("Invalid HMAC. Dropping the packet");
					continue;

				# Compute signature here
				hip_i2_packet = HIP.I2Packet();
				hip_i2_packet.set_senders_hit(shit);
				hip_i2_packet.set_receivers_hit(rhit);
				hip_i2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_i2_packet.set_version(HIP.HIP_VERSION);
				hip_i2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				buf = [];
				if r1_counter_param:
					buf += r1_counter_param.get_byte_buffer();

				buf += solution_param.get_byte_buffer() + \
						dh_param.get_byte_buffer() + \
						cipher_param.get_byte_buffer() + \
						hi_param.get_byte_buffer();

				if echo_signed:
					buf += echo_signed.get_byte_buffer();

				buf += transport_param.get_byte_buffer() + \
						mac_param.get_byte_buffer();
				
				original_length = hip_i2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				
				hip_i2_packet.set_length(int(packet_length / 8));
				buf = hip_i2_packet.get_buffer() + buf;

				signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
					logging.critical("Invalid signature. Dropping the packet");
				else:
					logging.debug("Signature is correct");

				logging.debug("Processing I2 packet %d" % (time.time() - st));
				
				st = time.time();

				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(rhit);
				hip_r2_packet.set_receivers_hit(shit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, shit, rhit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);
				mac_param = HIP.MAC2Parameter();
				
				mac_param.set_hmac(hmac.digest(bytearray(hip_r2_packet.get_buffer())));

				# Compute signature here
				
				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(rhit);
				hip_r2_packet.set_receivers_hit(shit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				buf = mac_param.get_byte_buffer();				
				original_length = hip_r2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r2_packet.set_length(int(packet_length / 8));
				buf = hip_r2_packet.get_buffer() + buf;
				signature_alg = RSASHA256Signature(privkey.get_key_info());
				signature = signature_alg.sign(bytearray(buf));

				signature_param = HIP.Signature2Parameter();
				signature_param.set_signature_algorithm(config.config["security"]["sig_alg"]);
				signature_param.set_signature(signature);

				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);
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
				logging.debug("Sending R2 packet to %s %d" % (dst_str, time.time() - st));
				hip_socket.sendto(
					bytearray(ipv4_packet.get_buffer()), 
					(dst_str, 0));

			elif hip_packet.get_packet_type() == HIP.HIP_R2_PACKET:
				
				st = time.time();

				logging.info("R2 packet");
				keymat = keymat_storage.get(Utils.ipv6_bytes_to_hex_formatted(shit), 
					Utils.ipv6_bytes_to_hex_formatted(rhit));
				(aes_key, hmac_key) = Utils.get_keys(keymat, hmac_alg, selected_cipher, rhit, shit);
				hmac = HMACFactory.get(hmac_alg, hmac_key);
				parameters       = hip_packet.get_parameters();
				
				hmac_param      = None;
				signature_param = None;

				for parameter in parameters:
					if isinstance(parameter, HIP.Signature2Parameter):
						logging.debug("Signature2 parameter");
						signature_param = parameter;
					if isinstance(parameter, HIP.MAC2Parameter):
						logging.debug("MAC2 parameter");	
						hmac_param = parameter;
				
				if not hmac_param:
					logging.critical("Missing HMAC parameter");
					continue;

				if not signature_param:
					logging.critical("Missing signature parameter");
					continue;

				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(shit);
				hip_r2_packet.set_receivers_hit(rhit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				if list(hmac.digest(bytearray(hip_r2_packet.get_buffer()))) != list(hmac_param.get_hmac()):
					logging.critical("Invalid HMAC. Dropping the packet");
					continue;
				else:
					logging.debug("HMAC is ok. Continue with signature");

				buf = [];
				hip_r2_packet = HIP.R2Packet();
				hip_r2_packet.set_senders_hit(shit);
				hip_r2_packet.set_receivers_hit(rhit);
				hip_r2_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
				hip_r2_packet.set_version(HIP.HIP_VERSION);
				hip_r2_packet.set_length(HIP.HIP_DEFAULT_PACKET_LENGTH);

				#hip_r2_packet.add_parameter(hmac_param);
				buf = list(hmac_param.get_byte_buffer());
				original_length = hip_r2_packet.get_length();
				packet_length = original_length * 8 + len(buf);
				hip_r2_packet.set_length(int(packet_length / 8));
				buf = hip_r2_packet.get_buffer() + buf;

				responders_public_key = pubkey_storage.get(Utils.ipv6_bytes_to_hex_formatted(shit), 
							Utils.ipv6_bytes_to_hex_formatted(rhit));
				signature_alg = RSASHA256Signature(responders_public_key.get_key_info());
				if not signature_alg.verify(signature_param.get_signature(), bytearray(buf)):
					logging.critical("Invalid signature. Dropping the packet");
				else:
					logging.debug("Signature is correct");

				logging.debug("Processing R2 packet %d" % time.time() - st);
				logging.debug("Ending HIP BEX %d" % time.time());
			elif hip_packet.get_packet_type() == HIP.HIP_UPDATE_PACKET:
				logging.info("UPDATE packet");
			elif hip_packet.get_packet_type() == HIP.HIP_NOTIFY_PACKET:
				logging.info("NOTIFY packet");
			elif hip_packet.get_packet_type() == HIP.HIP_CLOSE_PACKET:
				logging.info("CLOSE packet");
			elif hip_packet.get_packet_type == HIP.HIP_CLOSE_ACK_PACKET:
				logging.info("CLOSE ACK packet");
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
			buf = bytearray(ip_sec_socket.recv(MTU));
			ipv4_packet = IPv4.IPv4Packet(buf);
		except Exception as e:
			logging.critical("Exception occured. Dropping IPSec packet.");

def tun_if_loop():
	"""
	This loop is responsible for reading the packets 
	from the TUN interface
	"""
	logging.info("Starting the TUN interface loop");
	while True:
		try:
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
				logging.debug("Starting HIP BEX %d" % time.time);
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
				hip_i1_packet.set_senders_hit(shit);
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
				logging.debug("Sending I1 packet to %s %d" % (dst_str, time.time - st));
				hip_socket.sendto(bytearray(ipv4_packet.get_buffer()), (dst_str, 0));

				# Transition to an I1-Sent state
				hip_state.i1_sent();

			elif hip_state.is_established():
				# Send ESP packet to destination
				pass
		except Exception as e:
			logging.critical("Exception occured while processing packet from TUN interface. Dropping the packet.");


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
