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
sys.path.append(os.getcwd())

import utils
from utils.hit import HIT
from utils.hi import RSAHostID, ECDSAHostID, ECDSALowHostID

import crypto
from crypto.asymmetric import RSAPublicKey, RSAPrivateKey, ECDSAPublicKey, ECDSAPrivateKey, RSASHA256Signature, ECDSASHA384Signature, ECDSASHA1Signature

# Configuration
from config import config

pubkey = ECDSAPublicKey.load_pem(config.config["security"]["public_key"]);
privkey = ECDSAPrivateKey.load_pem(config.config["security"]["private_key"]);
hi = ECDSAHostID(pubkey.get_curve_id(), pubkey.get_x(), pubkey.get_y());
ipv6_address = HIT.get_hex_formated(hi.to_byte_array(), HIT.SHA384_OGA);

signature_alg = ECDSASHA384Signature(privkey.get_key_info());
signature = signature_alg.sign(bytearray("Hello world", encoding="ascii"));
print(list(signature))
signature_alg = ECDSASHA384Signature(pubkey.get_key_info());
print(signature_alg.verify(signature, bytearray("Hello world", encoding="ascii")));


responders_public_key = ECDSAPublicKey.load_from_params(hi.get_curve_id(), hi.get_x(), hi.get_y());
signature_alg = ECDSASHA384Signature(responders_public_key.get_key_info());
print(signature_alg.verify(signature, bytearray("Hello world", encoding="ascii")));