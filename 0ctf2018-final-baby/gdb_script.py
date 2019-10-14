# -*- coding: utf-8 -*-

#########################################################################
# File Name: gdb_script.py
# Created on : 2019-10-09 17:46:11
# Author: raycp
# Last Modified: 2019-10-13 02:52:41
# Description: script for debug lkm
#########################################################################

import gdb

ko_base = int(input("ko base: "), 16)

gdb.execute("target remote 127.0.0.1:1234")
gdb.execute("add-symbol-file ./baby.ko 0x%x"%(ko_base))
#gdb.execute("b")
