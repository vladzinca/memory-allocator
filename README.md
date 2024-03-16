# Memory allocator

## 💭 What is it?

This project is a custom C language memory management library, offering tailored solutions for efficient memory handling in your projects.

Using Linux memory management syscalls, such as `sbrk()`, `mmap()` and `munmap()`, the project implements minimal versions of the functions `malloc()`, `calloc()`, `realloc()`, and `free()` provided by the [C standard library](https://en.wikipedia.org/wiki/C_standard_library).

I worked on this for two days during April 2023 and it helped me further understand the problems of memory allocation, especially as this is currently a hot topic in areas such as cybersecurity and low-level programming.

## ⚙️ How to run it?

1.  Clone this repository.
2.  Build the solution file `libsomem.so` by running `make` inside `src/`.
3.  Build and run the automated testing script by running `make` and `python checker.py` inside `tests/` (I did not make the script myself). For my implementation, which does not take into account the `test-all` test, one should receive a `8.50` out of `9.00`.
4.  Enjoy!

## 🗣️ What does it do?

### Memory alignment

As in the original C language implementation, I am aligning allocated memory (i.e. all addresses are multiples of a given size) to **8 bytes** as required by 64 bit systems.

This is a space-time trade-off because memory blocks are padded so each can be read in one transaction. It also allows for atomicity when interacting with a block of memory.

### Block reusing

We consider a **block** to be a continuous zone of memory, allocated and managed by our implementation.

The structure `block_meta` is used to manage the metadata of a block. Each allocated zone comprises of a `block_meta` structure placed at the start, followed by data (payload).

For all functions, the returned address is that of the **payload** (not the `block_meta` structure).

```c
typedef struct block_meta {
	size_t size;
	int status;
	struct block_meta *next;
} block_meta;
```

![memory-block](./assets/memory-block.svg)

#### Block splitting

Reusing memory blocks improves the allocator's performance, but might lead to [internal memory fragmentation](https://en.wikipedia.org/wiki/Fragmentation_(computing)).

This happens when we allocate a size smaller than all available free blocks. If we use one larger block the remaining size of that block will be wasted since it cannot be used for another allocation.

To avoid this, a block is truncated to the required size and the remaining bytes are being used to create a new free block.

![Split Block](./assets/split-block.svg)

#### Block coalescing

There are cases when there is enough free memory for an allocation, but it is spread across multiple blocks that cannot be used.
This is called **external memory fragmentation**.

One technique to reduce external memory fragmentation is **block coalescing**, which implies merging adjacent free blocks to form a contiguous chunk.

![Coalesce Block Image](./assets/coalesce-blocks.svg)

Coalescing is used before searching for a block and in `os_realloc()` to expand the current block when possible.

### API

The program implements the following API:

#### os_malloc()

```c
void *os_malloc(size_t size)
```

Allocates `size` bytes and returns a pointer to the allocated memory.

Chunks of memory smaller than `MMAP_THRESHOLD` are allocated with `sbrk()`. Bigger chunks are allocated using `mmap()`. The memory is uninitialized.

Passing `0` as `size` will return `NULL`.

#### os_calloc()

```c
void *os_calloc(size_t nmemb, size_t size)
```

Allocates memory for an array of `nmemb` elements of `size` bytes each and returns a pointer to the allocated memory.

Chunks of memory smaller than [`page_size`](https://man7.org/linux/man-pages/man2/getpagesize.2.html) are allocated with `sbrk()`. Bigger chunks are allocated using `mmap()`. The memory is set to zero.

Passing `0` as `nmemb` or `size` will return `NULL`.

#### os_realloc()

```c
void *os_realloc(void *ptr, size_t size)
```

Changes the size of the memory block pointed to by `ptr` to `size` bytes. If the size is smaller than the previously allocated size, the memory block will be truncated.

If `ptr` points to a block on heap, `os_realloc()` will first try to expand the block, rather than moving it. Otherwise, the block will be reallocated and its contents copied.

When attempting to expand a block followed by multiple free blocks, `os_realloc()` will coalesce them one at a time and verify the condition for each. Blocks will remain coalesced even if the resulting block will not be big enough for the new size.

Calling `os_realloc()` on a block that has `STATUS_FREE` should return `NULL`. This is a measure to prevent undefined behavior and make the implementation robust, it should not be considered a valid use case of `os_realloc()`.

Passing `NULL` as `ptr` will have the same effect as `os_malloc(size)`.
Passing `0` as `size` will have the same effect as `os_free(ptr)`.

#### os_free()

```c
void os_free(void *ptr)
```

Frees memory previously allocated by `os_malloc()`, `os_calloc()` or `os_realloc()`.

`os_free()` will not return memory from the heap to the OS by calling `sbrk()`, but rather mark it as free and reuse it in future allocations.

In the case of mapped memory blocks, `os_free()` will call `munmap()`.

## 🎯 What was my strategy?

My implementation uses a general allocation function, `general_allocation()`, which receives the size of the allocation and a threshold to decide whether to allocate using `sbrk()` or `mmap()`. In this context, functions `os_malloc()` and `os_calloc()` simply call this general function with the appropriate arguments.

I have exclusively used `sbrk()`, as it is simpler to understand than `brk()`.



Another interesting aspect is how I chose to proceed in cases where both the old and new blocks, in the context of `os_realloc()`, are/must be allocated with `sbrk()`. Namely, I used the `get_maximum_possible_size()` function, which calculates how much a given block can grow without needing to be moved, and based on the result of this function a decision is made on what to do next.

For resources, I only used the [manual pages](https://man7.org/linux/man-pages/man3/), which helped me a lot, especially for understanding the functions and the flags they should return upon failure.

## 🤔 Did you know?

Initially, `os_realloc()` had many branches, but I couldn't figure out which path a call would take because they weren't very well thought out. So, I tried to restructure the branches based on:

- whether the block needs to be increased or decreased in size
- whether the old block was allocated with `sbrk()` or `mmap()`
- whether the new block needs to be allocated with `sbrk()` or `mmap()`.

This structure made it much easier to understand what was happening and it worked. 🍕
