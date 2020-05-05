#!/bin/bash

algo=$1;
curve=$2;

supported_algorithms="RSA ECDSA";
found=0;
for i in $supported_algorithms;
do
	if [ "$i" = "$algo" ]
	then
		found=1;
		break;
	fi;
done;

if [ $found -eq 0 ]
then
	echo "Unsupported algorithm";
	echo "Possible algorithms: RSA, ECDSA";
	exit;
fi

if [ "$algo" = "RSA" ]
then
	openssl genrsa -out private.pem 2048
	openssl rsa -in private.pem -outform PEM -pubout -out public.pem
	#openssl rsa -text -in private.pem
	mv public.pem private.pem ../config/
fi

if [ "$algo" = "ECDSA" ]
then
	openssl ecparam -name $curve -genkey -noout -out private.pem
	openssl ec -in private.pem -pubout -out public.pem
	mv public.pem private.pem ../config/
fi


