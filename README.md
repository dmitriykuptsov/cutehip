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

ECDSALow is not supported due to used cryptographic library limitations

Once the keys are generated, run the responder:

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