ALL:
	gcc -O0 -static -o ./cpio/exp_double_fetch exp_double_fetch.c -lpthread
	gcc -O0 -static -o ./cpio/exp_side_channel exp_side_channel.c
	gcc -O0 -static -o ./cpio/exp_side_channel_payload exp_side_channel_payload.c
	cd cpio && find . | cpio -o --format=newc > ../core.cpio
	#cd cpio&&./gen_cpio.sh ../core.cpio

DOUBLE_FETCH:
	gcc -O0 -static -o ./cpio/exp_double_fetch exp_double_fetch.c -lpthread
	cd cpio && find . | cpio -o --format=newc > ../core.cpio

SIDE_CHANNEL:
	gcc -O0 -static -o ./cpio/exp_side_channel exp_side_channel.c
	gcc -O0 -static -o ./cpio/exp_side_channel_payload exp_side_channel_payload.c
	cd cpio && find . | cpio -o --format=newc > ../core.cpio



clean:
	rm ./cpio/exp_double_fetch
	rm ./cpio/exp_side_channel
	rm ./cpio/exp_side_channel_payload

