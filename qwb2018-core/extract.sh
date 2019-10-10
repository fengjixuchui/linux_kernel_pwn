#!/bin/bash

#########################################################################
# File Name: extract.sh
# Created on: 2019-10-06 00:29:12
# Author: raycp
# Last Modified: 2019-10-08 03:21:29
# Description: extract cpio file 
#########################################################################

mkdir cpio
cd cpio
cp ../$1 ./
cpio -idmv < $1
rm $1





