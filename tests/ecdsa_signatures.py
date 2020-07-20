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

pubkey = ECDSAPublicKey.load_pem(os.getcwd() + "/tests/public.pem");
privkey = ECDSAPrivateKey.load_pem(os.getcwd() + "/tests/private.pem");
hi = ECDSAHostID(pubkey.get_curve_id(), pubkey.get_x(), pubkey.get_y());

buf=bytearray([59, 52, 2, 33, 0, 0, 0, 0, 32, 1, 32, 2, 154, 180, 25, 30, 146, 202, 217, 103, 73, 133, 67, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 52, 16, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 135, 9, 0, 132, 1, 8, 110, 227, 147, 251, 152, 193, 186, 221, 183, 135, 143, 217, 8, 204, 239, 186, 65, 79, 68, 210, 209, 46, 52, 152, 222, 211, 212, 38, 65, 68, 228, 188, 146, 244, 221, 91, 245, 36, 110, 190, 93, 23, 128, 228, 26, 3, 73, 38, 154, 123, 31, 155, 254, 142, 206, 98, 84, 82, 81, 10, 38, 101, 44, 84, 1, 167, 144, 113, 168, 83, 207, 40, 54, 111, 173, 50, 30, 231, 224, 100, 40, 148, 177, 183, 204, 233, 242, 179, 40, 60, 127, 190, 63, 181, 183, 80, 178, 78, 3, 23, 205, 78, 70, 9, 117, 107, 90, 135, 38, 137, 194, 221, 118, 98, 122, 122, 119, 180, 98, 248, 89, 90, 43, 42, 188, 18, 157, 38, 245, 99, 0, 0, 0, 0, 0, 2, 67, 0, 6, 0, 4, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 2, 193, 0, 134, 0, 98, 32, 30, 0, 7, 0, 2, 167, 42, 178, 124, 51, 115, 97, 164, 106, 159, 63, 201, 150, 13, 234, 1, 175, 199, 213, 239, 139, 4, 185, 170, 223, 52, 249, 127, 14, 132, 170, 212, 49, 135, 50, 5, 240, 254, 179, 238, 166, 17, 18, 175, 66, 221, 249, 193, 81, 220, 133, 3, 142, 233, 181, 180, 215, 67, 212, 198, 252, 7, 168, 29, 72, 67, 216, 127, 33, 6, 116, 220, 215, 69, 187, 180, 154, 201, 100, 203, 157, 169, 215, 18, 241, 195, 20, 143, 119, 234, 144, 61, 177, 112, 68, 18, 100, 109, 105, 116, 114, 105, 121, 46, 107, 117, 112, 116, 115, 111, 118, 64, 115, 116, 114, 97, 110, 103, 101, 98, 105, 116, 46, 99, 111, 109, 0, 0, 0, 0, 0, 0, 2, 203, 0, 3, 16, 32, 48, 0, 1, 255, 0, 1, 9, 0, 0, 0, 8, 1, 0, 2, 15, 255, 0, 0])
sig=bytes([8, 197, 232, 63, 169, 84, 4, 220, 65, 242, 88, 156, 17, 57, 111, 169, 188, 229, 19, 94, 144, 106, 90, 61, 188, 212, 112, 51, 56, 76, 65, 117, 14, 179, 90, 78, 212, 117, 80, 224, 5, 100, 204, 31, 174, 136, 157, 89, 203, 198, 40, 234, 165, 114, 53, 94, 149, 70, 200, 97, 180, 166, 239, 76, 237, 24, 111, 88, 85, 22, 152, 46, 72, 49, 122, 81, 31, 50, 245, 233, 89, 186, 59, 144, 164, 133, 212, 61, 202, 223, 196, 255, 87, 248, 42, 166])

signature_alg = ECDSASHA384Signature(privkey.get_key_info());
signature = signature_alg.sign(buf);
print(list(signature));
print(list(sig));
print(signature == sig)
print(type(signature))
signature_alg = ECDSASHA384Signature(pubkey.get_key_info());
print(signature_alg.verify(signature, buf));
print(signature_alg.verify(sig, buf));

#responders_public_key = ECDSAPublicKey.load_from_params(hi.get_curve_id(), hi.get_x(), hi.get_y());
#signature_alg = ECDSASHA384Signature(privkey.get_key_info());
#print(signature_alg.verify(signature, buf));

#signature_alg = ECDSASHA384Signature(pubkey.get_key_info());
#print(signature_alg.verify(sig, buf));
