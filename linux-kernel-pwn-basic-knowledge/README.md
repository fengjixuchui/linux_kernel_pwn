# qemu-basic-knowledge

* extract-cpio.sh
	
	Description: script for extracting cpio file, may need to `gunzip xx.cpio.gz` first.

* extract-vmlinux.sh

	Description: script for extracting vmlinux from bzImage.

* Makefile

	Description: example how to compile a exp and compress the cpio dir.

* gdb_script.py

    Description: gdb script for debug a `lkm`.

    Usage: `gdb vmlinux -x gdb_script.py`
