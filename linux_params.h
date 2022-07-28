/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Linux Params struct definition
 *
 * Copied and adapted from coreboot's cbfstool
 *
 * 2003-09 by SONE Takeshi
 */

#ifndef LINUX_PARAMS_H
#define LINUX_PARAMS_H

#include <stdint.h>

#define LINUX_HEADER_OFFSET 0x1f1

// Value from the spec that can be used to validate the header.
#define LINUX_HEADER_SIGNATURE 0x53726448

// Macro that encodes the used Linux boot protocol version according to the spec.
#define TO_LINUX_BOOT_HEADER_VERSION(major, minor) \
    (major << 8 | minor)

#define E820MAX 32 /* number of entries in E820MAP */
struct e820entry {
    uint64_t addr; /* start of memory segment */
    uint64_t size; /* size of memory segment */
    uint32_t type; /* type of memory segment */
#define E820_RAM 1
#define E820_RESERVED 2
#define E820_ACPI 3 /* usable as RAM once ACPI tables have been read */
#define E820_NVS 4
};

/* Parameters passed to 32-bit part of Linux */
struct linux_params {
    uint8_t orig_x;             /* 0x00 */
    uint8_t orig_y;             /* 0x01 */
    uint16_t ext_mem_k;         /* 0x02 -- EXT_MEM_K sits here */
    uint16_t orig_video_page;   /* 0x04 */
    uint8_t orig_video_mode;    /* 0x06 */
    uint8_t orig_video_cols;    /* 0x07 */
    uint16_t unused2;           /* 0x08 */
    uint16_t orig_video_ega_bx; /* 0x0a */
    uint16_t unused3;           /* 0x0c */
    uint8_t orig_video_lines;   /* 0x0e */
    uint8_t orig_video_isVGA;   /* 0x0f */
    uint16_t orig_video_points; /* 0x10 */

    /* VESA graphic mode -- linear frame buffer */
    uint16_t lfb_width;  /* 0x12 */
    uint16_t lfb_height; /* 0x14 */
    uint16_t lfb_depth;  /* 0x16 */
    uint32_t lfb_base;   /* 0x18 */
    uint32_t lfb_size;   /* 0x1c */
    uint16_t cl_magic;   /* 0x20 */
#define CL_MAGIC_VALUE 0xA33F
    uint16_t cl_offset;      /* 0x22 */
    uint16_t lfb_linelength; /* 0x24 */
    uint8_t red_size;        /* 0x26 */
    uint8_t red_pos;         /* 0x27 */
    uint8_t green_size;      /* 0x28 */
    uint8_t green_pos;       /* 0x29 */
    uint8_t blue_size;       /* 0x2a */
    uint8_t blue_pos;        /* 0x2b */
    uint8_t rsvd_size;       /* 0x2c */
    uint8_t rsvd_pos;        /* 0x2d */
    uint16_t vesapm_seg;     /* 0x2e */
    uint16_t vesapm_off;     /* 0x30 */
    uint16_t pages;          /* 0x32 */
    uint8_t reserved4[12];   /* 0x34 -- 0x3f reserved for future expansion */

    // struct apm_bios_info apm_bios_info;   /* 0x40 */
    uint8_t apm_bios_info[0x40];
    // struct drive_info_struct drive_info;  /* 0x80 */
    uint8_t drive_info[0x20];
    // struct sys_desc_table sys_desc_table; /* 0xa0 */
    uint8_t sys_desc_table[0x140];
    uint32_t alt_mem_k;         /* 0x1e0 */
    uint8_t reserved5[4];       /* 0x1e4 */
    uint8_t e820_map_nr;        /* 0x1e8 */
    uint8_t reserved6[8];       /* 0x1e9 */
                                /* This next variable is to show where
                                 * in this struct the Linux setup_hdr
                                 * is located. It does not get filled in.
                                 * We may someday find it useful to use
                                 * its address. */
    uint8_t setup_hdr;          /* 0x1f1  */
    uint16_t mount_root_rdonly; /* 0x1f2 */
    uint8_t reserved7[4];       /* 0x1f4 */
    uint16_t ramdisk_flags;     /* 0x1f8 */
#define RAMDISK_IMAGE_START_MASK 0x07FF
#define RAMDISK_PROMPT_FLAG 0x8000
#define RAMDISK_LOAD_FLAG 0x4000
    uint8_t reserved8[2];             /* 0x1fa */
    uint16_t orig_root_dev;           /* 0x1fc */
    uint8_t reserved9[1];             /* 0x1fe */
    uint8_t aux_device_info;          /* 0x1ff */
    uint8_t reserved10[2];            /* 0x200 */
    uint8_t param_block_signature[4]; /* 0x202 */
    uint16_t param_block_version;     /* 0x206 */
    uint8_t reserved11[8];            /* 0x208 */
    uint8_t loader_type;              /* 0x210 */
#define LOADER_TYPE_LOADLIN 1
#define LOADER_TYPE_BOOTSECT_LOADER 2
#define LOADER_TYPE_SYSLINUX 3
#define LOADER_TYPE_ETHERBOOT 4
#define LOADER_TYPE_KERNEL 5
    uint8_t loader_flags;               /* 0x211 */
    uint8_t reserved12[2];              /* 0x212 */
    uint32_t kernel_start;              /* 0x214 */
    uint32_t initrd_start;              /* 0x218 */
    uint32_t initrd_size;               /* 0x21c */
    uint8_t reserved13[8];            /* 0x220 */
    uint32_t cmd_line_ptr;              /* 0x228 */
    uint32_t initrd_addr_max;           /* 0x22c */
    uint32_t kernel_alignment;          /* 0x230 */
    uint8_t relocatable_kernel;         /* 0x234 */
    uint8_t min_alignment;              /* 0x235 */
    uint16_t xloadflags;                /* 0x236 */
    uint32_t cmdline_size;              /* 0x238 */
    uint32_t hardware_subarch;          /* 0x23C */
    uint64_t hardware_subarch_data;     /* 0x240 */
    uint32_t payload_offset;            /* 0x248 */
    uint32_t payload_length;            /* 0x24c */
    uint64_t setup_data;                /* 0x250 */
    uint64_t pref_address;              /* 0x258 */
    uint32_t init_size;                 /* 0x260 */
    uint8_t reserved14[0x6c];           /* 0x264 */
    struct e820entry e820_map[E820MAX]; /* 0x2d0 */
    uint8_t reserved15[688];            /* 0x550 */
#define COMMAND_LINE_SIZE 256
    /* Command line is copied here by 32-bit i386/kernel/head.S.
     * So I will follow the boot protocol, rather than putting it
     * directly here. --ts1 */
    uint8_t command_line[COMMAND_LINE_SIZE]; /* 0x800 */
    uint8_t reserved16[1792];                /* 0x900 - 0x1000 */
};

#endif /* LINUX_PARAMS_H */
