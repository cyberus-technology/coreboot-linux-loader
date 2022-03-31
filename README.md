# Coreboot Kernel Loader

This repository contains code for building a [coreboot](https://www.coreboot.org/) payload which
directly boots into a kernel that is available in memory.

Supported kernels are:

* Linux kernel image. The boot follows the Linux [x86 32-bit Boot
Protocol](https://www.kernel.org/doc/html/latest/x86/boot.html#bit-boot-protocol).
* 32 bit ELF binary. The boot is [Multiboot](https://www.gnu.org/software/grub/manual/multiboot/multiboot.html) compliant.

The payload assumes that a qemu [fw_cfg](https://github.com/qemu/qemu/blob/master/docs/specs/fw_cfg.txt) device is available and obtains the exact memory addresses from this device. During the boot process, the payload inspects the following items in `fw_cfg`:

- `opt/de.cyberus-technology/kernel_addr`: (mandatory) the start address of the kernel in
  memory
- `opt/de.cyberus-technology/initrd_addr`: (optional) the start address of the raw initrd image in
  memory
- `opt/de.cyberus-technology/initrd_size_addr`: (optional) the address of the 32-bit value in memory
  which holds the size of the initrd image
- `opt/de.cyberus-technology/cmdline_addr`: (optional) the address of the command line string in memory

Files in this directory have been frankensteined from coreboot's sources, in particular:

- `Makefile` from `payloads/libpayload/sample`
- `linux_params.h` from `util/cbfstool/linux.h`
- `fw_cfg.[h/c]` from `mainboard/emulation/qemu-i440fx/`

## Building

The build process depends on coreboot's [libpayload](https://www.coreboot.org/Libpayload)
and assumes that the necessary cross-compile toolchain is available in `$PATH`.

```
$ export LIBPAYLOAD_DIR=<libpayload install directory>
$ make
```

## Running

After adding the payload of this repository to a coreboot image with `cbfstool`, it can be used in
qemu to boot a linux kernel like this:

```
# Adding integers to qemu's fw_cfg device is a bit awkward because you can only add files
# or strings, so we need to create simple files which contain the little-endian byte representation
# of the respective addresses.

echo -n -e "\x00\x00\x00\x40" > kernel_addr
echo -n -e "\x00\x00\x00\x60" > initrd_addr
echo -n -e "\x00\x00\x00\x20" > initrd_size_addr
echo -n -e "\x00\x00\x00\x10" > cmdline_addr
echo -n -e "earlyprintk=ttyS0 console=ttyS0\x00" > cmdline_file

qemu-system-x86_64 -bios "${COREBOOT_FILE}" -nographic -serial mon:stdio -m 2G -enable-kvm \
  -device loader,addr=0x40000000,file="${KERNEL_FILE}",force-raw=on \
  -device loader,addr=0x60000000,file="${INITRD_FILE}",force-raw=on \
  -device loader,addr=0x10000000,file=./cmdline_file,force-raw=on \
  -device loader,addr=0x20000000,data=$(stat --printf="%s" "${INITRD_FILE}"),data-len=4 \
  -fw_cfg opt/de.cyberus-technology/kernel_addr,file=./kernel_addr \
  -fw_cfg opt/de.cyberus-technology/initrd_addr,file=./initrd_addr \
  -fw_cfg opt/de.cyberus-technology/cmdline_addr,file=./cmdline_addr \
  -fw_cfg opt/de.cyberus-technology/initrd_size_addr,file=./initrd_size_addr
```
