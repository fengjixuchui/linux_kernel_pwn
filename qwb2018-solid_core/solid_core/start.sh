qemu-system-x86_64 \
-m 256M \
-kernel ./bzImage \
-initrd  ./solid_core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1  kaslr" \
-cpu qemu64,+smep,+smap \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-s \
-nographic  -enable-kvm \
