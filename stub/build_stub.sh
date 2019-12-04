gcc -std=gnu99 -pedantic -fno-stack-protector -m64 -DARCH_AMD64 -o pack_common.c.o -c pack_common.c
gcc -std=gnu99 -pedantic -fno-stack-protector -m64 -DARCH_AMD64 -o aes.c.o -c aes.c
ar qc libstubamd64.a pack_common.c.o aes.c.o
ranlib libstubamd64.a

as --64 -o pack_amd64.s.o pack_amd64.s

ld -static -Ai386:x86-64 --oformat elf64-x86-64 -m elf_x86_64 pack_amd64.s.o -o stub_linux_amd64  -L/usr/lib/gcc/x86_64-linux-gnu/7 -L/lib/x86_64-linux-gnu/ libstubamd64.a -lc -lgcc

rm *.o
rm *.a
