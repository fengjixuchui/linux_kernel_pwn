# -*- coding: utf-8 -*-

#########################################################################
# File Name: gdb_script.py
# Created on : 2019-10-09 17:46:11
# Author: raycp
# Last Modified: 2019-10-11 01:09:01
# Description:
#########################################################################

import gdb
import sys
ko_base = int(input("ko base: "), 16)

gdb.execute("target remote 127.0.0.1:1234")
gdb.execute("add-symbol-file 0x%x"%(ko_base))
#gdb.execute("b")
