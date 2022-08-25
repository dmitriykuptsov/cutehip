# About

This is the replacement for the Java-based implementation of Host Indentity Protocol (HIP) version 2.

The solution was tested on Ubuntu 18.04, but in general, all Ubuntu like platforms should work fine.
We have also tested the implmentation on Raspberry PI.

# Introduction

Host Identity Protocol, or HIP, is layer 3.5 solution,
which was initially designed to split the dual role of the IP address: 
locator and identifier. Using HIP protocol one can solve not
only mobility problems, but also establish authenticated secure
channel. This repository contains the implementation of HIP and 
IPSec protocols using Python.

At the moment the development is ongoing. Linux was selected as a target system and all the 
development currently done for this operating system.

Cryptographic library was missing Diffie-Hellman and Elliptic Curve Diffie-Hellman so we 
have implemented these protocols in Python. We have also made some measurements just to
understand how well Python copes with these computation intensive tasks.

# Usage

Currently RSA and ECDSA (HI) algorithms for Host Identity are supported. To test the implementation one
needs to first install the needed libraries.

```
$ sudo pip3 install pycryptodome
$ sudo pip3 install netifaces
```

Make sure also net-tools are installed (needed for ifconfig):

```
$ sudo apt-get install net-tools
```
Clone the repository on both machines as follows:

```
$ git clone https://github.com/dmitriykuptsov/cutehip.git
$ cd cutehip
```

Then generate the keys on both initiator and responder as follows (only small keys are supported
at the moment, because fragmentation does not work. We have tested the implementation using RSA 
with 4096 bits modulus)

```
$ bash tools/genkey.sh gen RSA 1024
```

or (to create ECDSA key pair)
```
$ bash tools/genkey.sh gen ECDSA secp384r1
```

ECDSALow curve is not supported due to used cryptographic library limitations (it is basically, too insecure).

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
Copy the HIT and pad it with zeros if needed.

Then repeat the operation on intiator.

Update the hosts file (on initiator)
```
$ echo "<RHIT> <IP>" >> config/hosts
```

Remember to pad HIT with zeros if needed (ifconfig tool strips off unneeded zeros).

Run the initiator
```
$ sudo python3 cutehipd
```

We have added a simple firewall. So make sure you have added the rules to config/rules (the first
HIT in the rule is the source HIT and the second HIT is the destination (or responder's)
HIT. The rule can either deny or allow the communication with the hosts. Restart the responder
once the rules are in place.

Test the connection
```
$ ssh pi@<RHIT>
```

You should get security association installed once HIP BEX completes.

# Contact information

Would like to contact the author please send an email to dmitriy.kuptsov@strangebit.io
