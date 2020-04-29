from tinyec import registry

import sys
import os
sys.path.append(os.getcwd() + "/../crypto/");

from ecdh import ECDHBrainpool256, ECDHNIST256, ECDHNIST384, ECDHNIST521, ECDHSECP160R1, ECDH

def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

print("Doing TINYEC...")
curve = registry.get_curve('brainpoolP256r1')
alicePrivKey = 244;
alicePubKey = alicePrivKey * curve.g
print("Alice public key:", compress(alicePubKey))
bobPrivKey = 123;
bobPubKey = bobPrivKey * curve.g
print("Bob public key:", compress(bobPubKey))
print("Now exchange the public keys (e.g. through Internet)")
aliceSharedKey = alicePrivKey * bobPubKey
print("Alice shared key:", compress(aliceSharedKey))
bobSharedKey = bobPrivKey * alicePubKey
print("Bob shared key:", compress(bobSharedKey))
print("Equal shared keys:", aliceSharedKey == bobSharedKey)

print("Doing ECDHBrainpool256...")
ecdh1 = ECDHBrainpool256();
ecdh2 = ECDHBrainpool256();
ecdh1.set_private_key(alicePrivKey);
pub1 = ecdh1.generate_public_key();
print("Alice public key:", compress(pub1))
ecdh2.set_private_key(bobPrivKey);
pub2 = ecdh2.generate_public_key();
print("Bob public key:", compress(pub2));
sec1 = ecdh1.compute_shared_secret(pub2);
sec2 = ecdh2.compute_shared_secret(pub1);
print("Equal shared keys:", sec1.x == sec2.x and sec1.y == sec2.y);

for i in range(0, 10):
	#print("Doing ECDHBrainpool256...")
	ecdh1 = ECDHNIST256();
	ecdh2 = ECDHNIST256();
	ecdh1.generate_private_key();
	pub1 = ecdh1.generate_public_key();
	#print("Alice public key:", compress(pub1))
	ecdh2.generate_private_key();
	pub2 = ecdh2.generate_public_key();
	#print("Bob public key:", compress(pub2));
	sec1 = ecdh1.compute_shared_secret(pub2);
	sec2 = ecdh2.compute_shared_secret(pub1);
	print("Equal shared keys:", sec1.x == sec2.x and sec1.y == sec2.y);

for i in range(0, 10):
	ecdh1 = ECDHSECP160R1();
	ecdh2 = ECDHSECP160R1();
	ecdh1.generate_private_key();
	pub1 = ecdh1.generate_public_key();
	#print("Alice public key:", compress(pub1))
	ecdh2.generate_private_key();
	pub2 = ecdh2.generate_public_key();
	#print("Bob public key:", compress(pub2));
	sec1 = ecdh1.compute_shared_secret(pub2);
	sec2 = ecdh2.compute_shared_secret(pub1);
	print("Equal shared keys:", sec1.x == sec2.x and sec1.y == sec2.y);

print("Doing RFC4753 test vectors");
ecdh1 = ECDHNIST256();
ecdh1.set_private_key(0xC88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433)
pub1 = ecdh1.generate_public_key();
assert pub1.x == 0xDAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180
assert pub1.y == 0x5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3
ecdh2 = ECDHNIST256();
ecdh2.set_private_key(0xC6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53);
pub2 = ecdh2.generate_public_key();
assert pub2.x == 0xD12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63
assert pub2.y == 0x56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB
sec = ecdh1.compute_shared_secret(pub2);
assert sec.x == 0xD6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE
assert sec.y == 0x522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2

ecdh1 = ECDHNIST384();
ecdh1.set_private_key(0x099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194)
pub1 = ecdh1.generate_public_key();
assert pub1.x == 0x667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA;
assert pub1.y == 0x9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C;
ecdh2 = ECDHNIST384();
ecdh2.set_private_key(0x41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC);
pub2 = ecdh2.generate_public_key();
assert pub2.x == 0xE558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571;
assert pub2.y == 0xDCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C;
sec = ecdh1.compute_shared_secret(pub2);
assert sec.x == 0x11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746;
assert sec.y == 0xA2A9F38EF5CAFBE2347CF7EC24BDD5E624BC93BFA82771F40D1B65D06256A852C983135D4669F8792F2C1D55718AFBB4;

ecdh1 = ECDHNIST521();
ecdh1.set_private_key(0x0037ADE9319A89F4DABDB3EF411AACCCA5123C61ACAB57B5393DCE47608172A095AA85A30FE1C2952C6771D937BA9777F5957B2639BAB072462F68C27A57382D4A52);
pub1 = ecdh1.generate_public_key();
assert pub1.x == 0x0015417E84DBF28C0AD3C278713349DC7DF153C897A1891BD98BAB4357C9ECBEE1E3BF42E00B8E380AEAE57C2D107564941885942AF5A7F4601723C4195D176CED3E;
assert pub1.y == 0x017CAE20B6641D2EEB695786D8C946146239D099E18E1D5A514C739D7CB4A10AD8A788015AC405D7799DC75E7B7D5B6CF2261A6A7F1507438BF01BEB6CA3926F9582;
ecdh2 = ECDHNIST521();
ecdh2.set_private_key(0x0145BA99A847AF43793FDD0E872E7CDFA16BE30FDC780F97BCCC3F078380201E9C677D600B343757A3BDBF2A3163E4C2F869CCA7458AA4A4EFFC311F5CB151685EB9);
pub2 = ecdh2.generate_public_key();
assert pub2.x == 0x00D0B3975AC4B799F5BEA16D5E13E9AF971D5E9B984C9F39728B5E5739735A219B97C356436ADC6E95BB0352F6BE64A6C2912D4EF2D0433CED2B6171640012D9460F;
assert pub2.y == 0x015C68226383956E3BD066E797B623C27CE0EAC2F551A10C2C724D9852077B87220B6536C5C408A1D2AEBB8E86D678AE49CB57091F4732296579AB44FCD17F0FC56A;
sec = ecdh1.compute_shared_secret(pub2);
assert sec.x == 0x01144C7D79AE6956BC8EDB8E7C787C4521CB086FA64407F97894E5E6B2D79B04D1427E73CA4BAA240A34786859810C06B3C715A3A8CC3151F2BEE417996D19F3DDEA;
assert sec.y == 0x01B901E6B17DB2947AC017D853EF1C1674E5CFE59CDA18D078E05D1B5242ADAA9FFC3C63EA05EDB1E13CE5B3A8E50C3EB622E8DA1B38E0BDD1F88569D6C99BAFFA43;
