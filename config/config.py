config = {
	"network": {
		"tun_name": "hip0",                                    # Interface name
		"mtu": 1400                                            # MTU
	},
	"security": {
		"public_key": "./config/public.pem",                   # ECDSA/RSA public key
		"private_key": "./config/private.pem",                 # ECDSA/RSA private key
		"sig_alg": 0x5,                                        # RSA
		"hash_alg": 0x2,                                       # SHA-256
		"puzzle_difficulty": 0x10,                             # 16 bits
		"puzzle_lifetime_exponent": 37,                        # 32 seconds
		"diffie_hellamn_group": 0x8,                           # ECDH NIST 384 group
		"hip_cipher": 0x4,                                     # AES-256 CBC
		#"supported_DH_groups": [0x9, 0x8, 0x7, 0x3, 0x4, 0xa], # ECDHNIST521, ECDHNIST384, ECDHNIST256, DH5, DH15, ECDHSECP160R1
		"supported_DH_groups": [0x3, 0x4, 0xa], # ECDHNIST521, ECDHNIST384, ECDHNIST256, DH5, DH15, ECDHSECP160R1
		"supported_ciphers": [0x2, 0x4],                       # AES128CBC, AES256CBC
		"supported_hit_suits": [0x10, 0x20, 0x30],             # SHA256, SHA384, SHA1
		"supported_transports": [0x0FFF]                       # IPSec
	},
	"resolver": {
		"hosts_file": "./config/hosts",
		"domain_identifier": {                                 # Domain identifier type and value
			"type": 0x1,                                       # FQDN
			"value": "strangebit.com"                          # FQDN value
		}
	},
}
