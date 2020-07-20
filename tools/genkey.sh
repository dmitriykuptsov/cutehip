#!/bin/bash

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# This is utility allows users to generate RSA and ECDSA key pairs

path=$(dirname $0)
cd $path/../;

command=$1;
algo=$2;
curve=$3;
modulus=$3;

if [ "$command" = "" ]
then
	command="help";
fi

if [ "$command" = "gen" ]
then

	supported_algorithms="RSA ECDSA";
	supported_key_lengths="512 1024 2048 4096";
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
		openssl genrsa -out private.pem $modulus
		openssl rsa -in private.pem -outform PEM -pubout -out public.pem
		#openssl rsa -text -in private.pem
		mv public.pem private.pem ./config/
	fi

	if [ "$algo" = "ECDSA" ]
	then
		openssl ecparam -name $curve -genkey -noout -out private.pem
		openssl ec -in private.pem -pubout -out public.pem
		mv public.pem private.pem ./config/
	fi
fi

if [ "$command" = "curves" ]
then
	openssl ecparam -list_curves
fi

if [ "$command" = "help" ]
then
	echo "bash genkey.sh [command] [params]";
	echo "  help - print this help"
	echo "  curves - print available curves"
	echo "  modulus - specify the RSA modulus (512 1024 2048 4096)"
	echo "  gen [RSA|ECDSA] [modulus|curve]"
fi

