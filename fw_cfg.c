/* SPDX-License-Identifier: GPL-2.0-only */

// This file implements simple fw_cfg accessor functions. It utilizes the port IO interface,
// even if the MMIO interface would be available. The implementation is mostly copied from
// coreboot's sources and adapted to work with libpayload.

#include "fw_cfg.h"

#include <libpayload.h>

bool fw_cfg_present()
{
    static const char qsig[] = "QEMU";
    unsigned char sig[FW_CFG_SIG_SIZE];
    _Static_assert(sizeof(qsig) >= sizeof(sig),
                   "Expected fw_cfg signature is too large for the target array");

    bool detected = 0;

    fw_cfg_get(FW_CFG_SIGNATURE, sig, sizeof(sig));
    detected = memcmp(sig, qsig, sizeof(sig)) == 0;
    printf("QEMU: firmware config interface %s\n", detected ? "detected" : "not found");
    return detected;
}

static void fw_cfg_select(uint16_t entry)
{
    outw(entry, FW_CFG_PORT_CTL);
}

static void fw_cfg_read(void *dst, size_t dstlen)
{
    insb(FW_CFG_PORT_DATA, dst, dstlen);
}

void fw_cfg_get(uint16_t entry, void *dst, size_t dstlen)
{
    fw_cfg_select(entry);
    fw_cfg_read(dst, dstlen);
}

uint16_t fw_cfg_selector_for(const char *name)
{
    FWCfgFile file;
    size_t count = 0;

    fw_cfg_select(FW_CFG_FILE_DIR);
    fw_cfg_read(&count, sizeof(count));
    count = be32toh(count);

    for (size_t i = 0; i < count; i++) {
        fw_cfg_read(&file, sizeof(file));
        if (strcmp(file.name, name) == 0) {
            file.size = be32toh(file.size);
            file.select = be16toh(file.select);
            printf("QEMU: firmware config: Found '%s' at %x\n", name, file.select);
            return file.select;
        }
    }
    printf("QEMU: firmware config: Couldn't find '%s'\n", name);
    return 0;
}
