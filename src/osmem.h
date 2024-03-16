/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "printf.h"
#include "helpers.h"

void coalesce_blocks(struct block_meta *heap_start);
struct block_meta *check_for_block_reuse(struct block_meta *heap_start, size_t needed_size);
void *general_allocation(size_t size, size_t threshold);

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
