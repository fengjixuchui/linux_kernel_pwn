ALL:
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/exp_hijack_prctl exp_hijack_prctl.c
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/reverse_shell reverse_shell.c
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/exp_vdso exp_vdso.c
	gcc -O0 -o ./rootfs/sudo_timer sudo_timer.c
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/exp_task_struct exp_task_struct.c
	cd rootfs && find . | cpio -o --format=newc > ../rootfs.cpio

VDSO:
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/exp_vdso exp_vdso.c
	gcc -O0 -o ./rootfs/sudo_timer sudo_timer.c
	cd rootfs && find . | cpio -o --format=newc > ../rootfs.cpio

TASK_STRUCT:
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/exp_task_struct exp_task_struct.c
	cd rootfs && find . | cpio -o --format=newc > ../rootfs.cpio
	#cd cpio&&./gen_cpio.sh ../core.cpio

HIJACK_PRCTL:
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/exp_hijack_prctl exp_hijack_prctl.c
	gcc -O0 -static -D_GNU_SOURCE -o ./rootfs/reverse_shell reverse_shell.c
	cd rootfs && find . | cpio -o --format=newc > ../rootfs.cpio


clean:
	-rm ./rootfs/exp_task_struct
	-rm ./rootfs/exp_vdso
	-rm ./rootfs/sudo_timer
	-rm ./rootfs/exp_hijack_prctl
	-rm ./rootfs/reverse_shell

