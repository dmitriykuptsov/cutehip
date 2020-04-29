# Add upper directory to path
import sys
import os
sys.path.append("./../packets")
sys.path.append("./../utils")

import HIP
from misc import Utils, Math

dh_groups_param = HIP.DHGroupListParameter();
dh_groups_param.add_groups([0x9, 0x8, 0x7, 0x3, 0x4, 0x0a]);

shit = bytearray([0x20,0x01,0x20,0x01,0x28,0x28,0xa1,0x23,0x51,0x1f,0x8d,0x3f,0xcd,0x63,0x0d,0x68]);
rhit = bytearray([0x20,0x01,0x20,0x01,0xea,0xbb,0x93,0x38,0x8d,0xb9,0x07,0x57,0x26,0x39,0x81,0x76]);

src = Math.int_to_bytes(
	Utils.ipv4_to_int("192.168.0.121"));

dst = Math.int_to_bytes(
	Utils.ipv4_to_int("192.168.0.103"));

hip_i1_packet = HIP.I1Packet();
hip_i1_packet.set_senders_hit(shit);
hip_i1_packet.set_receivers_hit(rhit);

hip_i1_packet.set_next_header(HIP.HIP_IPPROTO_NONE);
hip_i1_packet.set_version(HIP.HIP_VERSION);
hip_i1_packet.add_parameter(dh_groups_param);

checksum = Utils.hip_ipv4_checksum(
	src, 
	dst,
	HIP.HIP_PROTOCOL, 
	56, 
	hip_i1_packet.get_buffer());
assert checksum == 0x6d9a;
