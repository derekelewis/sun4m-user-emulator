all:
	/home/dlewis/work/repos/third-party/buildroot/output/host/bin/sparc-linux-gcc -m32 -mcpu=v8 -nostdlib start.S hello_world.c -static -o hello_world
	/home/dlewis/work/repos/third-party/buildroot/output/host/bin/sparc-linux-gcc -m32 -mcpu=v8 -nostdlib start.S primes.c -static -o primes
clean:
	rm -f hello_world primes
