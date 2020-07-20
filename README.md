# About

This is the replacement for the Java-based implementation of Host Indentity Protocol (HIP) version 2

# Introduction
At the moment the development is ongoing. Linux was selected as a target system and all the 
development currently done for this operating system.

Cryptographic library was missing Diffie-Hellman and Elliptic Curve Diffie-Hellman so we 
have implemented these protocols in Python. We have also made some measurements just to
understand how well Python copes with these computation intensive tasks.

# Usage

Currently only RSA algorithm for Host Identity is supported. To test the implementation one
need to first install the needed libraries.

```
$ pip3 install pycryptodome
```

Then generate the keys on both initiator and responder as follows

```
$ bash tools/genkey.sh gen RSA 4096
```
Run the responder:

```
$ sudo python3 cutehipd
```

Check the HIT of the responder

```
$ ifconfig hip0
```

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
