// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"

struct block_meta* metadata = NULL, *heap_start;

/* goes through all the memory blocks and tries
   to coalesce those that are freed */
void coalesce_blocks(struct block_meta *heap_start)
{
	struct block_meta *metadata = heap_start;

	while (metadata != NULL)
	{
		while (metadata->status == STATUS_FREE && metadata->next != NULL &&
			   metadata->next->status == STATUS_FREE)
		{
			metadata->size = metadata->size + sizeof(struct block_meta) + metadata->next->size;
			metadata->status = STATUS_FREE;
			metadata->next = metadata->next->next;
		}
		metadata = metadata->next;
	}
}

/* searches for a block that can be reused (either free and of
   the correct size or free and not followed by a block) */
struct block_meta *check_for_block_reuse(struct block_meta *heap_start, size_t needed_size)
{
	if (heap_start == NULL)
		return NULL;

	struct block_meta *metadata = heap_start;

	do
	{
		if ((metadata->status == STATUS_FREE && metadata->size >= needed_size) ||
			(metadata->status == STATUS_FREE && metadata->next == NULL))
			return metadata;

		metadata = metadata->next;

	} while (metadata != NULL);

	return NULL;
}

/* the function used by malloc and calloc to allocate memory */
void *general_allocation(size_t size, size_t threshold)
{
	/* compute the size the block would have if aligned */
	size_t real_size;

	if (size % 8 == 0)
		real_size = size;
	else
		real_size = size - size % 8 + 8;

	if (sizeof(struct block_meta) + real_size < threshold)
	{
		/* allocate real_size bytes using sbrk() */
		if (metadata == NULL)
		{
			/* allocate the first sbrk block on heap */
			metadata = sbrk(0);
			DIE(metadata == (void *)-1, "sbrk() failed");
			heap_start = metadata;
			void *p = sbrk(MMAP_THRESHOLD);
			DIE(p == (void *)-1, "sbrk() failed");

			metadata->size = MMAP_THRESHOLD - sizeof(struct block_meta);
			metadata->status = STATUS_ALLOC;
			metadata->next = NULL;

			/* if there exists enough unused space for a free block, split the block */
			if (sizeof(struct block_meta) + real_size + sizeof(struct block_meta) + 8 <= MMAP_THRESHOLD)
			{
				struct block_meta *free_block = (struct block_meta *)((char *)metadata +
												 sizeof(struct block_meta) + real_size);

				free_block->size = MMAP_THRESHOLD - 2 * sizeof(struct block_meta) - real_size;
				free_block->status = STATUS_FREE;
				free_block->next = NULL;

				metadata->size = real_size;
				metadata->next = free_block;
			}

			/* return a pointer to the allocated memory space */
			return metadata + 1;
		}
		else
		{
			/* before deciding what to do with the new block,
			   coalesce the free blocks */
			coalesce_blocks(heap_start);

			/* look to reuse a free block */
			struct block_meta *reusable_block = check_for_block_reuse(heap_start, real_size);

			if (reusable_block == NULL)
			{
				/* there were no suitable free blocks found, allocate another
				   one with sbrk() */
				metadata->next = sbrk(real_size + sizeof(struct block_meta));
				DIE(metadata->next == (void *)-1, "sbrk() failed");
				metadata = metadata->next;

				metadata->size = real_size;
				metadata->status = STATUS_ALLOC;
				metadata->next = NULL;
			}
			else
			{
				/* there is a suitable free block at the
				   location pointed by reusable_block */
				metadata = reusable_block;
				metadata->status = STATUS_ALLOC;

				/* the block was not large enough, allocate
				   the rest using sbrk() */
				if (real_size > metadata->size)
				{
					void *p = sbrk(real_size - metadata->size);
					DIE(p == (void *)-1, "sbrk() failed");
					metadata->size = real_size;
				}
			}

			/* if there exists enough unused space for a free block, split the block */
			if (real_size + sizeof(struct block_meta) + 8 <= metadata->size)
			{
				struct block_meta *free_block = (struct block_meta *)((char *)metadata +
												 sizeof(struct block_meta) + real_size);

				free_block->size = metadata->size - sizeof(struct block_meta) - real_size;
				free_block->status = STATUS_FREE;
				free_block->next = metadata->next;

				metadata->size = real_size;
				metadata->next = free_block;
			}

			return metadata + 1;
		}
	}
	else
	{
		/* allocate real_size bytes using mmap() */
		void *p = mmap(0, real_size + sizeof(struct block_meta),
					   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(p == MAP_FAILED, "mmap() failed");

		struct block_meta *metadata = (struct block_meta *) p;

		metadata->size = real_size;
		metadata->status = STATUS_MAPPED;
		metadata->next = NULL;

		return metadata + 1;
	}
}

void *os_malloc(size_t size)
{
	/* Implement os_malloc */
	if (size == 0)
		return NULL;

	return general_allocation(size, MMAP_THRESHOLD);
}

void os_free(void *ptr)
{
	/* Implement os_free */
	if (ptr == NULL)
		return;

	struct block_meta *metadata = (struct block_meta *)ptr;
	metadata = metadata - 1;

	if (metadata->status == STATUS_ALLOC)
	{
		metadata->status = STATUS_FREE;
	}
	else
	{
		int i = munmap(ptr - sizeof(struct block_meta), metadata->size + sizeof(struct block_meta));
		DIE(i == -1, "munmap() failed");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* Implement os_calloc */
	if (nmemb == 0 || size == 0)
		return NULL;

	void *p = general_allocation(nmemb * size, getpagesize());

	memset(p, 0, nmemb * size);

	return p;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
