# About

This is the replacement for the Java-based implementation of Host Indentity Protocol (HIP)

# Introduction
At the moment the development is ongoing. Linux was selected as a target system and all the 
development currently done for this operating system.

Cryptographic library was missing Diffie-Hellman and Elliptic Curve Diffie-Hellman so we 
have implemented these protocols in Python. We have also made some measurements just to
understand how well Python copes with these computation intensive tasks.