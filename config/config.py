config = {
	"network": {
		"tun_name": "hip0",                    # Interface name
		"mtu": 1500                            # MTU
	},
	"security": {
		"public_key": "./config/public.pem",   # ECDSA/RSA public key
		"private_key": "./config/private.pem", # ECDSA/RSA private key
		"sig_alg": 0x5,                        # RSA
		"hash_alg": 2,                         # SHA-256
		"puzzle_difficulty": 16,               # 16 bits
		"puzzle_lifetime_exponent": 37,        # 32 seconds
		"diffie_hellamn_group": 8,             # ECDH NIST 384 group
		"hip_cipher_suit": 4,                  # AES-256 CBC
	},
	"resolver": {
		"hosts_file": "./config/hosts",
		"domain_identifier": {                 # Domain identifier type and value
			"type": 0x1,                       # FQDN
			"value": "strangebit.com"          # FQDN value
		}
	},
}
