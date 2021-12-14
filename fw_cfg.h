/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FW_CFG_H
#define FW_CFG_H

#include <libpayload.h>

enum fw_cfg_enum {
    FW_CFG_SIGNATURE,
    FW_CFG_ID,
    FW_CFG_UUID,
    FW_CFG_RAM_SIZE,
    FW_CFG_NOGRAPHIC,
    FW_CFG_NB_CPUS,
    FW_CFG_MACHINE_ID,
    FW_CFG_KERNEL_ADDR,
    FW_CFG_KERNEL_SIZE,
    FW_CFG_KERNEL_CMDLINE,
    FW_CFG_INITRD_ADDR,
    FW_CFG_INITRD_SIZE,
    FW_CFG_BOOT_DEVICE,
    FW_CFG_NUMA,
    FW_CFG_BOOT_MENU,
    FW_CFG_MAX_CPUS,
    FW_CFG_KERNEL_ENTRY,
    FW_CFG_KERNEL_DATA,
    FW_CFG_INITRD_DATA,
    FW_CFG_CMDLINE_ADDR,
    FW_CFG_CMDLINE_SIZE,
    FW_CFG_CMDLINE_DATA,
    FW_CFG_SETUP_ADDR,
    FW_CFG_SETUP_SIZE,
    FW_CFG_SETUP_DATA,
    FW_CFG_FILE_DIR
};

#define FW_CFG_PORT_CTL 0x0510
#define FW_CFG_PORT_DATA 0x0511

#define FW_CFG_MAX_FILE_PATH 56
#define FW_CFG_SIG_SIZE 4

typedef struct FWCfgFile {
    uint32_t size;   /* file size */
    uint16_t select; /* write this to 0x510 to read it */
    uint16_t reserved;
    char name[FW_CFG_MAX_FILE_PATH];
} FWCfgFile;

void fw_cfg_get(uint16_t entry, void *dst, size_t dstlen);
bool fw_cfg_present();
uint16_t fw_cfg_selector_for(const char *name);

#endif /* FW_CFG_H */
