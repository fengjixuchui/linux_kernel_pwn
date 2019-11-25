# -*- coding: utf-8 -*-

#########################################################################
# File Name: send.py
# Created on : 2019-11-23 08:53:54
# Author: raycp
# Last Modified: 2019-11-23 09:53:54
# Description: send file exp to local host
#########################################################################
#!/usr/bin/env python2
from pwn import *

p = remote("49.235.24.33", 9998)
def send_command(cmd, print_cmd = True, print_resp = False):
    if print_cmd:
        log.info(cmd)

    p.sendlineafter("$", cmd)
    resp = p.recvuntil("$")

    if print_resp:
        log.info(resp)

    p.unrecv("$")
    return resp

def send_file(name):
    file = read(name)
    f = b64e(file)

    send_command("rm /tmp/a.gz.b64")
    send_command("rm /tmp/a.gz")
    send_command("rm /tmp/a")

    size = 800
    print len(f)
    for i in range(len(f)/size + 1):
        log.info("Sending chunk {}/{}".format(i, len(f)/size))
        send_command("echo -n '{}'>>/tmp/a.gz.b64".format(f[i*size:(i+1)*size]), False)

    send_command("cat /tmp/a.gz.b64 | base64 -d > /tmp/a.gz")
    send_command("gzip -d /tmp/a.gz")
    send_command("chmod +x /tmp/a")

def exploit():
    ## need gzip exp here
    send_file("exp.gz")
    #send_command("/home/note/a")
    #p.sendline("/a")
    p.interactive()

if __name__ == "__main__":

    #context.log_level = 'debug'
    #s = ssh(host="xxx", port=xxx, user="xxx", password="xxx", timeout=5)
    #p = s.shell('/bin/sh')
    #p = process("./run.sh")
    exploit()
