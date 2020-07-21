# About

This is the replacement for the Java-based implementation of Host Indentity Protocol (HIP) version 2

# Introduction
At the moment the development is ongoing. Linux was selected as a target system and all the 
development currently done for this operating system.

Cryptographic library was missing Diffie-Hellman and Elliptic Curve Diffie-Hellman so we 
have implemented these protocols in Python. We have also made some measurements just to
understand how well Python copes with these computation intensive tasks.

# Usage

Currently RSA and ECDSA (HI) algorithms for Host Identity are supported. To test the implementation one
need to first install the needed libraries.

```
$ pip3 install pycryptodome
$ pip3 install netifaces
```

```
$ git clone https://github.com/dmitriykuptsov/cutehip.git
$ cd cutehip
```

Then generate the keys on both initiator and responder as follows

```
$ bash tools/genkey.sh gen RSA 4096
```

or (to create ECDSA key pair)
```
$ bash tools/genkey.sh gen ECDSA secp384r1
```

ECDSALow is not supported due to used cryptographic library limitations.

The next step is to change the configuration. If RSA is used, set sig_alg to 0x5, and hash 
algorithm (hash_alg) to 0x1. If ECDSA is used for signatures, set sig_alg 0x7, and hash
algorithm (hash_alg) to 0x2. Also make sure you set the correct order of the cipher algorithm
and Diffie-Hellman algorithm (the first one in the list will be used during the BEX). Also 
the first cipher will be used for encrypting/decrypting ESP payload.

Once the keys are generated and configuration file is modified, run the responder:

```
$ sudo python3 cutehipd
```

Check the HIT of the responder (first you need to SSH on the responder and only then execute the below command):

```
$ ifconfig hip0
```

Then repeat the operation on intiator.

Update the hosts file (on initiator)
```
$ echo "<HIT> <IP>" >> config/hosts
```

Run the initiator
```
$ sudo python3 cutehipd
```

Test the connection
```
$ ssh pi@<HIT>
```

You should get secrutity association installed once HIP BEX completes.