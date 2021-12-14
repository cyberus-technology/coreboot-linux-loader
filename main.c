/* Copyright Cyberus Technology GmbH *
 *        All rights reserved        */

/* SPDX-License-Identifier: GPL-2.0-only  */


#include "linux_params.h"
#include "fw_cfg.h"

#include <libpayload-config.h>
#include <libpayload.h>

static void die_on(bool condition, char *string, ...)
{
    if (condition) {
        va_list ptr;
        va_start(ptr, string);
        vprintf(string, ptr);
        va_end(ptr);
        halt();
    }
}

struct bzimage_params {
    size_t bzimage_addr;
    size_t initrd_addr;
    size_t initrd_size_addr;
    size_t cmdline_addr;
};

static struct bzimage_params initialize_from_fw_cfg()
{
    die_on(!fw_cfg_present(), "Firmware config device not found\n");
    struct bzimage_params params;

    uint16_t selector;

    selector = fw_cfg_selector_for("opt/de.cyberus-technology/bzimage_addr");
    if (selector != 0) {
        fw_cfg_get(selector, &params.bzimage_addr, sizeof(params.bzimage_addr));
    }

    selector = fw_cfg_selector_for("opt/de.cyberus-technology/initrd_addr");
    if (selector != 0) {
        fw_cfg_get(selector, &params.initrd_addr, sizeof(params.initrd_addr));
    }

    selector = fw_cfg_selector_for("opt/de.cyberus-technology/initrd_size_addr");
    if (selector != 0) {
        fw_cfg_get(selector, &params.initrd_size_addr, sizeof(params.initrd_size_addr));
    }

    selector = fw_cfg_selector_for("opt/de.cyberus-technology/cmdline_addr");
    if (selector != 0) {
        fw_cfg_get(selector, &params.cmdline_addr, sizeof(params.cmdline_addr));
    }

    return params;
}

int main(void)
{
    struct bzimage_params bzimage_params = initialize_from_fw_cfg();

    die_on(bzimage_params.bzimage_addr == 0, "bzImage start address not found!\n"
           "The VMM does not offer a Linux kernel via fw-cfg. Is the relevant config option missing?\n");

    printf("Loading Linux kernel from address: 0x%lx\n", bzimage_params.bzimage_addr);

    char *linux_header_end = (char *)(bzimage_params.bzimage_addr + 0x201);
    size_t linux_header_size = 0x202 + *linux_header_end - LINUX_HEADER_OFFSET;

    struct linux_params *boot_params = malloc(sizeof(*boot_params));
    memset(boot_params, 0, sizeof(*boot_params));

    die_on(LINUX_HEADER_OFFSET + linux_header_size > sizeof(*boot_params),
           "Invalid linux header size");

    memcpy((char *)boot_params + LINUX_HEADER_OFFSET,
           (char *)(bzimage_params.bzimage_addr + LINUX_HEADER_OFFSET),
           linux_header_size); // load header

    die_on(boot_params->param_block_version < 0x0205,
           "Kernel does not support boot protocol >= 2.05\n");
    die_on(
        !boot_params->relocatable_kernel,
        "Kernel is not relocatable. The Linux kernel must be built with CONFIG_RELOCATABLE=y\n");
    die_on(bzimage_params.bzimage_addr % boot_params->kernel_alignment != 0,
           "Kernel needs to be aligned at 0x%x\n", boot_params->kernel_alignment);

    printf("Setting up E820 map\n");
    // Coreboot already obtained the memory map. Simply copy it over into the kernel params.
    boot_params->e820_map_nr = lib_sysinfo.n_memranges;
    for (int i = 0; i < lib_sysinfo.n_memranges; i++) {
        boot_params->e820_map[i].addr = lib_sysinfo.memrange[i].base;
        boot_params->e820_map[i].size = lib_sysinfo.memrange[i].size;
        boot_params->e820_map[i].type = lib_sysinfo.memrange[i].type;
    }

    // There is a maximum size for the command line, which could be obtained from the kernel
    // header if the boot protocol version is >= 2.06. We don't check anything here and
    // simply assume the user knows what they are doing.
    if (bzimage_params.cmdline_addr != 0) {
        boot_params->cmd_line_ptr = bzimage_params.cmdline_addr;
    }

    if (bzimage_params.initrd_addr != 0) {
        boot_params->initrd_start = bzimage_params.initrd_addr;
        boot_params->initrd_size = *(u32 *)bzimage_params.initrd_size_addr;

        die_on(boot_params->initrd_start + boot_params->initrd_size
                   > boot_params->initrd_addr_max,
               "Initrd area exceeds maximum initrd address as required by the kernel\n");
    }

    const uint8_t custom_loader_type = 0xFF;
    boot_params->loader_type = custom_loader_type;

    // According to the Linux boot protocol, we should set up a simple GDT here. Both 32-bit
    // and 64-bit Linux set their own GDT right after the entry point, and simply jumping to
    // the entry address works without any issues so far, so we're skipping this.

    uint8_t setup_sects = boot_params->setup_hdr;

    if (setup_sects == 0) {
        setup_sects = 4;
    }

    size_t entry_ptr_32bit = bzimage_params.bzimage_addr + (setup_sects + 1) * 512;

    // An overflowing unsigned integer addition will simply wrap. Such an overflow can be
    // detected by checking whether the result is smaller than one of the original values.
    die_on(entry_ptr_32bit < bzimage_params.bzimage_addr,
           "32bit entry pointer lies beyond 4G\n");

    asm volatile("jmp *%[entry_ptr];" ::[entry_ptr] "r"(entry_ptr_32bit), "S"(boot_params),
                 "m"(boot_params));

    __builtin_unreachable();
}
