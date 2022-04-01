/* Copyright Cyberus Technology GmbH *
 *        All rights reserved        */

/* SPDX-License-Identifier: GPL-2.0-only  */


#include "elf_boot.h"
#include "linux_params.h"
#include "fw_cfg.h"

#include <libpayload-config.h>
#include <libpayload.h>

static void die_on(const bool condition, const char *string, ...)
{
    if (condition) {
        va_list ptr;
        va_start(ptr, string);
        vprintf(string, ptr);
        va_end(ptr);
        halt();
    }
}

struct boot_params {
    uintptr_t kernel_addr;
    uintptr_t initrd_addr;
    uintptr_t initrd_size_addr;
    uintptr_t cmdline_addr;
};

enum boot_protocol {
    UNKNOWN,
    LINUX,
    ELF,
};

static struct boot_params get_boot_params_from_fw_cfg();
static enum boot_protocol get_boot_protocol(struct boot_params);
void linux_boot(struct boot_params);
void elf_boot(struct boot_params);

int main(void)
{
    const struct boot_params params = get_boot_params_from_fw_cfg();
    enum boot_protocol boot_protocol = get_boot_protocol(params);

    switch (boot_protocol) {
    case LINUX:
        linux_boot(params);
        break;
    case ELF:
        elf_boot(params);
        break;
    default:
        die_on(
            true,
            "Failed to recognize kernel file format. Supported format is bzImage and 32-bit ELF.\n");
    }
}

// Identify the type of the kernel.
static enum boot_protocol get_boot_protocol(const struct boot_params params)
{
    die_on(params.kernel_addr == 0, "Did not find the address of kernel.\n");

    // ELF binaries begin with a magic number.
    // Check this first because the ELF contents might accidentally match other checks.
    if (memcmp((const void *)params.kernel_addr, ELF_MAGIC, 4) == 0) {
        return ELF;
    }

    // Linux kernel supporting the "new" boot protocol have a magic number at a specific offset.
    // See https://www.kernel.org/doc/Documentation/x86/boot.txt.
    if (memcmp((const void *)(params.kernel_addr + 0x202), "HdrS", 4) == 0) {
        return LINUX;
    }

    return UNKNOWN;
}

static struct boot_params get_boot_params_from_fw_cfg()
{
    struct boot_params params = {
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
void linux_boot(const struct boot_params boot_params)
{
    die_on(
        boot_params.kernel_addr == 0,
        "bzImage start address not found!\n"
        "The VMM does not offer a Linux kernel via fw-cfg. Is the relevant config option missing?\n");

    printf("Loading Linux kernel from address: 0x%lx\n", boot_params.kernel_addr);

    char *linux_header_end = (char *)(boot_params.kernel_addr + 0x201);
    size_t linux_header_size = 0x202 + *linux_header_end - LINUX_HEADER_OFFSET;

    struct linux_params *linux_params = malloc(sizeof(*linux_params));
    memset(linux_params, 0, sizeof(*linux_params));

    die_on(LINUX_HEADER_OFFSET + linux_header_size > sizeof(*linux_params),
           "Invalid linux header size");

    memcpy((char *)linux_params + LINUX_HEADER_OFFSET,
           (const char *)(boot_params.kernel_addr + LINUX_HEADER_OFFSET),
           linux_header_size); // load header

    die_on(linux_params->param_block_version < 0x0205,
           "Kernel does not support boot protocol >= 2.05\n");
    die_on(
        !linux_params->relocatable_kernel,
        "Kernel is not relocatable. The Linux kernel must be built with CONFIG_RELOCATABLE=y\n");
    die_on(boot_params.kernel_addr % linux_params->kernel_alignment != 0,
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
    if (boot_params.cmdline_addr != 0) {
        linux_params->cmd_line_ptr = boot_params.cmdline_addr;
    }

    if (boot_params.initrd_addr != 0) {
        linux_params->initrd_start = boot_params.initrd_addr;
        linux_params->initrd_size = *(u32 *)boot_params.initrd_size_addr;

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

    uintptr_t entry_ptr_32bit = boot_params.kernel_addr + (setup_sects + 1) * 512;

    // An overflowing unsigned integer addition will simply wrap. Such an overflow can be
    // detected by checking whether the result is smaller than one of the original values.
    die_on(entry_ptr_32bit < boot_params.kernel_addr, "32-bit entry pointer lies beyond 4G\n");

    asm volatile("jmp *%[entry_ptr];" ::[entry_ptr] "r"(entry_ptr_32bit), "S"(linux_params),
                 "m"(linux_params));

    __builtin_unreachable();
}

// Boot an ELF binary according to the Multiboot specification.
//
// This boot method:
//
// 1. Extracts the ELF binary.
// 2. Prepares Multiboot information (to pass the optional command line).
// 3. Jumps to the extracted ELF's entry point.
void elf_boot(const struct boot_params params)
{
    die_on(
        params.kernel_addr == 0,
        "kernel start address not found!\n"
        "The VMM does not offer an ELF via fw-cfg. Is the relevant config option missing?\n");

    // Minimal (32-bit) ELF loading.
    const struct elf32_header *elf = (struct elf32_header *)params.kernel_addr;
    printf("Loading ELF from address: %p\n", elf);

    die_on(elf->class != ELF_CLASS_32BIT, "Unsupported ELF kernel. ELF is not 32-bit.\n");
    die_on(elf->data != ELF_DATA_LITTLE_ENDIAN,
           "Unsupported ELF kernel. ELF uses big endianness.\n");
    die_on(elf->version != ELF_VERSION,
           "Unsupported ELF kernel. ELF version is unsupported.\n");
    die_on(elf->type != ELF_TYPE_EXECUTABLE, "Unsupported ELF kernel. Unknown ELF type 0x%x!\n",
           elf->type);
    die_on(elf->ehsize != sizeof(struct elf32_header),
           "Unsupported ELF kernel. ELF header size of %d does not match 32-bit ELF file.\n",
           elf->ehsize);
    die_on(
        elf->phentsize != sizeof(struct elf32_program_header),
        "Unsupported ELF kernel. ELF program header size %d does not match 32-bit ELF file!\n",
        elf->phentsize);

    // The ELF file is loaded to memory already. We need that start address to copy its contents
    // (such as code and data) to the correct location.
    const uint8_t *elf_addr_in_memory = (const uint8_t *)elf;

    // Each entry in the program header table describes a memory region.
    // We prepare the contents of each region, but ignore the access rights.
    struct elf32_program_header *current_program_header =
        (struct elf32_program_header *)(elf_addr_in_memory + elf->phoff);

    for (uint16_t i = 0; i < elf->phnum; i++) {
        const uint8_t *current_elf_segment_in_memory =
            elf_addr_in_memory + current_program_header->offset;

        printf(
            "Loading ELF segment (type 0x%x, offset 0x%x, vaddr 0x%x, paddr 0x%x, filesize 0x%x, memsize 0x%x)\n",
            current_program_header->type, current_program_header->offset,
            current_program_header->vaddr, current_program_header->paddr,
            current_program_header->filesize, current_program_header->memsize);

        // TODO: Assert that ELF contents don't overwrite anything.
        // The sysinfo lib could be used to detect whether the destination is usable RAM.
        // When adding such a check, determine which memory regions coreboot uses
        // so that upcoming memory allocations don't conflict.

        // At this point, we have a 1:1 mapping of virtual and physical memory. Use the physical
        // address because the ELF program may modify page tables to use a custom virtual memory
        // layout that matches the segment's vaddr.
        const uintptr_t dest_addr = (uintptr_t)current_program_header->paddr;
        die_on(dest_addr == 0,
               "Unsupported ELF kernel. ELF segment has physical address 0x0.\n");

        // Copy contents of the region from the ELF file.
        memcpy((void *)dest_addr, current_elf_segment_in_memory,
               current_program_header->filesize);

        // Fill remainder of the region with zeroes (used for BSS segment).
        memset((void *)(dest_addr + current_program_header->filesize), 0,
               current_program_header->memsize - current_program_header->filesize);

        current_program_header++;
    }

    // Prepare Multiboot information.
    struct mb_boot_information_required *mbinfo = malloc(sizeof(*mbinfo));
    memset(mbinfo, 0, sizeof(*mbinfo));

    if (params.cmdline_addr != 0) {
        mbinfo->flags |= FLAG_CMDLINE_BIT;
        mbinfo->cmdline = params.cmdline_addr;
    }

    // Jump to the ELF's entry point.
    //
    // Coreboot has already prepared the machine state specified in
    // https://www.gnu.org/software/grub/manual/multiboot/multiboot.html#Machine-state
    asm volatile("jmp *%[entry_ptr];" ::[entry_ptr] "r"(elf->entry),
                 // Pass address of Multiboot information structure in EBX.
                 "b"(mbinfo),
                 // Report being a multiboot v1 loader in EAX.
                 "a"(MULTIBOOT_BOOTLOADER_MAGIC));

    __builtin_unreachable();
}
