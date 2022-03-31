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
    size_t kernel_addr;
    size_t initrd_addr;
    size_t initrd_size_addr;
    size_t cmdline_addr;
};

enum boot_protocol {
    UNKNOWN,
    LINUX,
};

static struct bzimage_params get_boot_params_from_fw_cfg();
static enum boot_protocol get_boot_protocol(struct bzimage_params);
void linux_boot(struct bzimage_params);

int main(void)
{
    struct bzimage_params params = get_boot_params_from_fw_cfg();
    enum boot_protocol boot_protocol = get_boot_protocol(params);

    switch (boot_protocol) {
    case LINUX:
        linux_boot(params);
        break;
    default:
        die_on(true, "Failed to recognize kernel file format. Supported format is bzImage.\n");
    }
}

// Identify the type of the kernel.
static enum boot_protocol get_boot_protocol(struct bzimage_params params)
{
    size_t kernel_addr = params.kernel_addr;

    die_on(kernel_addr == 0, "Did not find the address of kernel.\n");

    // Linux kernel supporting the "new" boot protocol have a magic number at a specific offset.
    // See https://www.kernel.org/doc/Documentation/x86/boot.txt.
    if (memcmp((uint32_t *)(kernel_addr + 0x202), "HdrS", 4) == 0) {
        return LINUX;
    }

    return UNKNOWN;
}

static struct bzimage_params get_boot_params_from_fw_cfg()
{
    struct bzimage_params params = {
        .kernel_addr = 0, .initrd_addr = 0, .initrd_size_addr = 0, .cmdline_addr = 0};

    uint16_t selector;

    selector = fw_cfg_selector_for("opt/de.cyberus-technology/kernel_addr");
    if (selector != 0) {
        fw_cfg_get(selector, &params.kernel_addr, sizeof(params.kernel_addr));
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

// Linux boot follows the Linux x86 32-bit Boot Protocol
// (https://www.kernel.org/doc/html/latest/x86/boot.html#bit-boot-protocol).
void linux_boot(struct bzimage_params bzimage_params)
{
    die_on(
        bzimage_params.kernel_addr == 0,
        "bzImage start address not found!\n"
        "The VMM does not offer a Linux kernel via fw-cfg. Is the relevant config option missing?\n");

    printf("Loading Linux kernel from address: 0x%lx\n", bzimage_params.kernel_addr);

    char *linux_header_end = (char *)(bzimage_params.kernel_addr + 0x201);
    size_t linux_header_size = 0x202 + *linux_header_end - LINUX_HEADER_OFFSET;

    struct linux_params *linux_params = malloc(sizeof(*linux_params));
    memset(linux_params, 0, sizeof(*linux_params));

    die_on(LINUX_HEADER_OFFSET + linux_header_size > sizeof(*linux_params),
           "Invalid linux header size");

    memcpy((char *)linux_params + LINUX_HEADER_OFFSET,
           (const char *)(bzimage_params.kernel_addr + LINUX_HEADER_OFFSET),
           linux_header_size); // load header

    die_on(linux_params->param_block_version < 0x0205,
           "Kernel does not support boot protocol >= 2.05\n");
    die_on(
        !linux_params->relocatable_kernel,
        "Kernel is not relocatable. The Linux kernel must be built with CONFIG_RELOCATABLE=y\n");
    die_on(bzimage_params.kernel_addr % linux_params->kernel_alignment != 0,
           "Kernel needs to be aligned at 0x%x\n", linux_params->kernel_alignment);

    printf("Setting up E820 map\n");
    // Coreboot already obtained the memory map. Simply copy it over into the kernel params.
    linux_params->e820_map_nr = lib_sysinfo.n_memranges;
    for (int i = 0; i < lib_sysinfo.n_memranges; i++) {
        linux_params->e820_map[i].addr = lib_sysinfo.memrange[i].base;
        linux_params->e820_map[i].size = lib_sysinfo.memrange[i].size;
        linux_params->e820_map[i].type = lib_sysinfo.memrange[i].type;
    }

    // There is a maximum size for the command line, which could be obtained from the kernel
    // header if the boot protocol version is >= 2.06. We don't check anything here and
    // simply assume the user knows what they are doing.
    if (bzimage_params.cmdline_addr != 0) {
        linux_params->cmd_line_ptr = bzimage_params.cmdline_addr;
    }

    if (bzimage_params.initrd_addr != 0) {
        linux_params->initrd_start = bzimage_params.initrd_addr;
        linux_params->initrd_size = *(u32 *)bzimage_params.initrd_size_addr;

        die_on(linux_params->initrd_start + linux_params->initrd_size
                   > linux_params->initrd_addr_max,
               "Initrd area exceeds maximum initrd address as required by the kernel\n");
    }

    const uint8_t custom_loader_type = 0xFF;
    linux_params->loader_type = custom_loader_type;

    // According to the Linux boot protocol, we should set up a simple GDT here. Both 32-bit
    // and 64-bit Linux set their own GDT right after the entry point, and simply jumping to
    // the entry address works without any issues so far, so we're skipping this.

    uint8_t setup_sects = linux_params->setup_hdr;

    if (setup_sects == 0) {
        setup_sects = 4;
    }

    size_t entry_ptr_32bit = bzimage_params.kernel_addr + (setup_sects + 1) * 512;

    // An overflowing unsigned integer addition will simply wrap. Such an overflow can be
    // detected by checking whether the result is smaller than one of the original values.
    die_on(entry_ptr_32bit < bzimage_params.kernel_addr,
           "32-bit entry pointer lies beyond 4G\n");

    asm volatile("jmp *%[entry_ptr];" ::[entry_ptr] "r"(entry_ptr_32bit), "S"(linux_params),
                 "m"(linux_params));

    __builtin_unreachable();
}
