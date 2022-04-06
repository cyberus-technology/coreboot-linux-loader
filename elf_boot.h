/* Copyright Cyberus Technology GmbH *
 *        All rights reserved        */

/* SPDX-License-Identifier: GPL-2.0-only  */

#ifndef ELF_BOOT_H
#define ELF_BOOT_H

#include <libpayload.h>

#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

// Required fields in the Multiboot information structure.
struct mb_boot_information_required {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
};

enum multiboot_info {
    FLAG_CMDLINE_BIT = 1 << 2,
};

const char ELF_MAGIC[] = {0x7f, 'E', 'L', 'F'};
const uint16_t ELF_CLASS_32BIT = 1;
const uint8_t ELF_TYPE_EXECUTABLE = 0x2;
const uint8_t ELF_DATA_LITTLE_ENDIAN = 1;
const uint8_t ELF_VERSION = 1;

struct elf32_header {
    uint32_t magic;
    uint8_t class;
    uint8_t data;
    uint8_t version;
    uint8_t osabi;
    uint8_t abiversion;
    uint8_t pad[7];
    uint16_t type;
    uint16_t machine;
    uint32_t eversion;
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};

struct elf32_program_header {
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesize;
    uint32_t memsize;
    uint32_t flags;
    uint32_t align;
};

#endif
