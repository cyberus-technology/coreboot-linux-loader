/* Copyright Cyberus Technology GmbH *
 *        All rights reserved        */

/* SPDX-License-Identifier: GPL-2.0-only  */

#ifndef MEMORY_REGION_H
#define MEMORY_REGION_H

#include <stddef.h>
#include <stdint.h>

struct memory_region {
    uintptr_t addr;
    size_t size;
};

// Returns true if two memory regions overlap.
static inline bool memory_regions_overlap(const struct memory_region first,
                                          const struct memory_region second)
{
    const struct memory_region lower = first.addr <= second.addr ? first : second;
    const struct memory_region higher = first.addr <= second.addr ? second : first;

    // When the higher region is not "behind" the lower region, the regions overlap.
    return higher.addr < lower.addr + lower.size;
}

static inline bool memory_region_contains(const struct memory_region container,
                                          const struct memory_region containee)
{
    return container.addr <= containee.addr
           && ((container.addr + container.size) >= (containee.addr + containee.size));
}

#endif
