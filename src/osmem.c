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

/* gets the maximum possible size the block described by
   metadata could take without being moved */
size_t get_maximum_possible_size(struct block_meta *metadata)
{
	size_t possible_size = 0;

	possible_size += metadata->size;

	while (metadata->next != NULL && metadata->next->status == STATUS_FREE)
	{
		possible_size += sizeof(struct block_meta) + metadata->next->size;
		metadata = metadata->next;
	}

	/* if the block is followed only by free blocks, we mark that with 0 */
	if (metadata->next == NULL)
		return 0;

	return possible_size;
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
	/* Implement os_realloc */
	if (ptr == NULL)
		return os_malloc(size);
	else if (size == 0)
	{
		os_free(ptr);
		return NULL;
	}

	struct block_meta *metadata = (struct block_meta *)ptr;
	metadata = metadata - 1;

	if (metadata->status == STATUS_FREE)
		return NULL;

	/* compute the new size of the block */
	size_t new_size;

	if (size % 8 == 0)
		new_size = size;
	else
		new_size = size - size % 8 + 8;

	if (new_size < metadata->size)
	{
		/* the block needs to be shrunk */
		if (metadata->status == STATUS_MAPPED)
		{
			/* the initial block was allocated using mmap() */
			if (sizeof(struct block_meta) + new_size >= MMAP_THRESHOLD)
			{
				/* the new block should be allocated using mmap() as well */
				void *p = mmap(0, new_size + sizeof(struct block_meta),
							   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
				DIE(p == MAP_FAILED, "mmap() failed");

				struct block_meta *old_metadata = metadata;
				struct block_meta *metadata = (struct block_meta *)p;

				metadata->size = new_size;
				metadata->status = STATUS_MAPPED;
				metadata->next = NULL;

				/* copy the contents of the old block into
				   the new space, and free the old block */
				memcpy(metadata + 1, old_metadata + 1, new_size);
				os_free(old_metadata + 1);

				return metadata + 1;
			}
			else if (sizeof(struct block_meta) + new_size < MMAP_THRESHOLD)
			{
				/* the new block should be allocated using sbrk(), let
				   os_malloc() do its job */
				void *p = os_malloc(new_size);

				struct block_meta *old_metadata = metadata;
				struct block_meta *metadata = (struct block_meta *)p;

				memcpy(metadata + 1, old_metadata + 1, new_size);
				os_free(old_metadata + 1);

				return metadata;
			}
		}
		else if (metadata->status == STATUS_ALLOC)
		{
			/* the initial block was allocated using sbrk(). Considering
			   the new size is even smaller, it makes sense to shrink it
			   in place */
			size_t old_size = metadata->size;

			/* if there exists enough unused space for a free block, split the block */
			if (new_size + sizeof(struct block_meta) + 8 <= old_size)
			{
				struct block_meta *free_block = (struct block_meta *)((char *)metadata +
												 sizeof(struct block_meta) + new_size);

				free_block->size = metadata->size - sizeof(struct block_meta) - new_size;
				free_block->status = STATUS_FREE;
				free_block->next = metadata->next;

				metadata->size = new_size;
				metadata->next = free_block;
			}

			return metadata + 1;
		}
	}
	else if (new_size > metadata->size)
	{
		/* the block needs to be expanded */
		if (metadata->status == STATUS_MAPPED)
		{
			/* the old block was allocated using mmap(), and the new block
			   is larger, so it should be allocated using mmap() too */
			void *p = mmap(0, new_size + sizeof(struct block_meta),
						   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
			DIE(p == MAP_FAILED, "mmap() failed");

			struct block_meta *old_metadata = metadata;
			struct block_meta *metadata = (struct block_meta *)p;

			metadata->size = new_size;
			metadata->status = STATUS_MAPPED;
			metadata->next = NULL;

			memcpy(metadata + 1, old_metadata + 1, new_size);
			os_free(old_metadata + 1);

			return metadata + 1;
		}
		else if (metadata->status == STATUS_ALLOC)
		{
			/* the old block was allocated using sbrk() */
			if (sizeof(struct block_meta) + new_size >= MMAP_THRESHOLD)
			{
				/* the new block should be allocated using mmap() */
				void *p = mmap(0, new_size + sizeof(struct block_meta),
							   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
				DIE(p == MAP_FAILED, "mmap() failed");

				struct block_meta *new_metadata = (struct block_meta *)p;

				new_metadata->size = new_size;
				new_metadata->status = STATUS_MAPPED;
				new_metadata->next = NULL;

				memcpy(new_metadata + 1, metadata + 1, metadata->size);

				os_free(metadata + 1);

				return new_metadata + 1;
			}
			else if (sizeof(struct block_meta) + new_size < MMAP_THRESHOLD)
			{
				/* both the old block and the new block are sbrk() size,
				   and we should first try to expand the old block in-place
				   (merge with adjacent free blocks) */
				size_t maximum_possible_size = get_maximum_possible_size(metadata);

				if (maximum_possible_size == 0)
				{
					/* can be expanded in-place by absorbing all upcoming free
					   blocks and then allocating the remaining size with sbrk() */
					while (metadata->next != NULL && metadata->size < new_size)
					{
						/* absorb all free blocks (merge them into our block) */
						metadata->size += sizeof(struct block_meta) + metadata->next->size;
						metadata->next = metadata->next->next;

						/* if we have covered new_size and included space that
						   could form a free block, split the block */
						if (new_size + sizeof(struct block_meta) + 8 <= metadata->size)
						{
							struct block_meta *free_block = (struct block_meta *)((char *)metadata +
															 sizeof(struct block_meta) + new_size);

							free_block->size = metadata->size - sizeof(struct block_meta) - new_size;
							free_block->status = STATUS_FREE;
							free_block->next = metadata->next;

							metadata->size = new_size;
							metadata->next = free_block;
						}
					}

					/* allocate the remaining size with sbrk() */
					if (metadata->size < new_size)
					{
						void *p = sbrk(new_size - metadata->size);
						DIE(p == (void *)-1, "sbrk() failed");
					}

					metadata->size = new_size;

					return metadata + 1;
				}
				else if (new_size <= maximum_possible_size)
				{
					/* can be expanded in-place just by absoring free blocks.
					   Compute the necessary size */
					int needed_space = (int)(new_size - metadata->size);

					while (metadata->next != NULL && needed_space > 0)
					{
						/* absorb free blocks. We are guaranteed there are
						   enough free memory blocks to grow into by the
						   get_maximum_possible_size() call */
						metadata->size = metadata->size + metadata->next->size +
										 sizeof(struct block_meta);
						metadata->next = metadata->next->next;

						needed_space = needed_space - metadata->next->size -
									   sizeof(struct block_meta);
					}

					/* if possible, mark the unnecessary space as free */
					if (needed_space + sizeof(struct block_meta) + 8 <= metadata->next->size)
					{
						struct block_meta *free_block = (struct block_meta *)
														((char *)metadata->next + needed_space);

						free_block->size = metadata->next->size - sizeof(struct block_meta) - needed_space;
						free_block->status = STATUS_FREE;
						free_block->next = metadata->next->next;

						metadata->size = metadata->size + needed_space;
						metadata->next = free_block;
					}

					return metadata + 1;
				}
				else if (new_size > maximum_possible_size)
				{
					/* block has to be move in order expand */
					void *p = os_malloc(new_size);

					struct block_meta *new_metadata = (struct block_meta *)p;
					new_metadata = new_metadata - 1;

					memcpy(new_metadata + 1, metadata + 1, metadata->size);
					os_free(metadata + 1);

					return new_metadata + 1;
				}
			}
		}
	}

	/* the new and old sizes are identical, simply return the pointer */
	return metadata + 1;
}
