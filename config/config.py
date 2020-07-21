config = {
	"network": {
		"tun_name": "hip0",                                    # Interface name
		"mtu": 1400                                            # MTU
	},
	"security": {
		"public_key": "./config/public.pem",                   # ECDSA/RSA public key
		"private_key": "./config/private.pem",                 # ECDSA/RSA private key
		"sig_alg": 0x7,                                        # RSA 5, ECDSA 7, ECDSA LOW 9, DSA 3
		"hash_alg": 0x2,                                       # SHA-256 0x1, SHA-384 0x2, SHA-1 0x3
		# If signature algorithm is ECDSA,
		# then HASH algorithm should be SHA-384,
		# HASH algorithm is the one that is used
		# to compute the HMAC, as well as to construct HIT
		"puzzle_difficulty": 0x10,                             # 16 bits
		"puzzle_lifetime_exponent": 37,                        # 32 seconds
		# Currently DH can be used ONLY with ECDSA because
		# fragmentation does not work
		"supported_DH_groups": [0x7, 0x9, 0x8, 0x3, 0x4, 0xa], # ECDHNIST521 (0x9), ECDHNIST384 (0x8), ECDHNIST256 (0x7), DH5 (0x3), DH15 (0x4), ECDHSECP160R1 (0xa)
		"supported_ciphers": [0x4, 0x2, 0x1],                  # NULL (0x1), AES128CBC (0x2), AES256CBC (0x4)
		"supported_hit_suits": [0x10, 0x20, 0x30],             # SHA256 (0x1), SHA384 (0x2), SHA1 (0x3)
		"supported_transports": [0x0FFF],                      # IPSec
		"supported_signatures": [0x5, 0x7, 0x9],               # DSA (0x3), RSA (0x5), ECDSA (0x7), ECDSA_LOW (0x9)
		"supported_esp_transform_suits": [0x7, 0x8, 0x9]        # NULL with HMAC-SHA-256 (0x7), AES-128-CBC with HMAC-SHA-256 (0x8), AES-256-CBC with HMAC-SHA-256 (0x9)
	},
	"resolver": {
		"hosts_file": "./config/hosts",
		"domain_identifier": {                                 # Domain identifier type and value
			"type": 0x2,                                       # FQDN 0x1, NAI 0x2
			"value": "dmitriy.kuptsov@strangebit.com"          # NAI value
		}
	},
	"general": {
		"i1_timeout_s": 20,
		"i1_retries": 3,
		"i2_retries": 3,
		"i2_timeout_s": 20,
		"update_timeout_s": 60,
		"close_timeout_s": 30,
		"UAL": 120,
		"MSL": 120,
		"EC": 120
	}
}

