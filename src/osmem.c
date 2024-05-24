// SPDX-License-Identifier: BSD-3-Clause

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/types.h>
#include "osmem.h"
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024)
#define PAYLOAD ((void *)(block + 1))

#define BLOCK_SIZE sizeof(struct block_meta)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MAP_ANONYMOUS	0x20		/* Don't use a file.  */
#define MAP_ANON	MAP_ANONYMOUS
#define LAST_ADDR ((char *)sbrk(0))

void *global_base;
int prealloc;

struct block_meta *get_block_ptr(void *ptr)
{
	return (struct block_meta *)ptr - 1;
}

struct block_meta *find_free(struct block_meta **last, size_t size)
{
	struct block_meta *current = (*last);

	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size >= size)
			return current;
		*last = current;
		current = current->next;
	}
	return NULL;
}

void *expand(struct block_meta *block, size_t size)
{
	size_t size_aligned = ALIGN(size);

	sbrk(size_aligned - ALIGN(block->size));
	DIE(sbrk(0) == (void *)-1, "sbrk failed");
	block->size = size;
	block->status = STATUS_ALLOC;
	return PAYLOAD;
}

struct block_meta *split(struct block_meta **block, size_t size)
{
	struct block_meta *new;
	struct block_meta *helper = (struct block_meta *)((char *)(*block) + size + BLOCK_SIZE);
	int aux = (*block)->size;

	(*block)->status = STATUS_ALLOC;
	(*block)->size = size;
	if (((char *)*block + (*block)->size + BLOCK_SIZE) < LAST_ADDR) {
		new = helper;
	} else {
		sbrk((char *)*block + (*block)->size + BLOCK_SIZE - LAST_ADDR);
		DIE(sbrk(0) == (void *)-1, "sbrk failed");
		new = helper;
	}
	new->size = aux - size - BLOCK_SIZE;
	new->status = STATUS_FREE;
	new->next = (*block)->next;
	new->prev = *block;
	(*block)->next = new;
	return new;
}

struct block_meta *request_calloc(struct block_meta *last, size_t size)
{
	struct block_meta *block;
	void *request;
	size_t total_size = ALIGN(size + BLOCK_SIZE);

	if (total_size >= (size_t)getpagesize()) {
		request = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(request == MAP_FAILED, "mmap");
		block = request;
		block->status = STATUS_MAPPED;
		block->size = size;
		block->next = NULL;
		if (last)
			last->next = block;
		return block;
	}

	block = sbrk(0);
	if (prealloc == 0) {
		request = sbrk(MMAP_THRESHOLD);
		DIE(request == (void *)-1, "sbrk failed");
		block->next = NULL;
		prealloc = 1;
		block->status = STATUS_ALLOC;
		if (last)
			last->next = block;
		block->size = size;
		return block;
	}
	request = sbrk(total_size);
	DIE(request == (void *)-1, "sbrk failed");
	block->next = NULL;
	block->status = STATUS_ALLOC;
	if (last)
		last->next = block;
	block->size = size;
	return block;
}

void *__calloc(size_t size)
{
	if (size <= 0)
		return NULL;
	struct block_meta *block;
	size_t size_aligned = ALIGN(size);
	struct block_meta *current =  global_base;

	while (current != NULL) {
		if (current->status == STATUS_FREE && current->next != NULL &&
			current->next->status == STATUS_FREE) {
			struct block_meta *next = current->next;

			current->size += next->size + BLOCK_SIZE;
			current->next = next->next;
			if (current->next != NULL)
				current->next->prev = current;
			else
				current = current->prev;
		}
		current = current->next;
	}

	if (global_base == NULL) {
		prealloc = 0;
		block = request_calloc(NULL, size);
		if (block == NULL)
			return NULL;
		global_base = block;
		return PAYLOAD;
	}
	struct block_meta *last = global_base;
	struct block_meta *free = find_free(&last, size);

	if (last->status == STATUS_FREE && last->size < size && free == NULL)
		return expand(last, size);
	if (free == NULL) {
		block = request_calloc(last, size);
		if (block == NULL)
			return NULL;
		return PAYLOAD;
	}
	if (free->size >= size_aligned + BLOCK_SIZE + ALIGNMENT) {
		block = free;
		struct block_meta *new = split(&block, size_aligned);

		if (new == NULL)
			return NULL;
		return PAYLOAD;
	}
	free->status = STATUS_ALLOC;
	block = free;
	return PAYLOAD;
}

struct block_meta *request(struct block_meta *last, size_t size)
{
	struct block_meta *block;
	void *request;
	size_t size_aligned = ALIGN(size);
	size_t total = size_aligned + BLOCK_SIZE;

	if (size >= MMAP_THRESHOLD) {
		request = mmap(NULL, total, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(request == MAP_FAILED, "mmap failed");
		block = request;
		block->size = size;
		block->next = NULL;
		if (last) {
			last->next = block;
			block->prev = last;
		} else {
			block->prev = global_base;
		}
		block->status = STATUS_MAPPED;
		return block;
	}
	block = sbrk(0);
	if (prealloc == 0) {
		sbrk(MMAP_THRESHOLD);
		DIE(sbrk(0) == (void *)-1, "sbrk failed");
		block->next = NULL;
		block->prev = global_base;
		block->status = STATUS_ALLOC;
		block->size = size;
		prealloc = 1;
		if (MMAP_THRESHOLD - size_aligned - BLOCK_SIZE > BLOCK_SIZE) {
			split(&block, size);
			return block;
		}
		return block;
	}
	request = sbrk(total);
	DIE(request == (void *)-1, "sbrk failed");
	block->next = NULL;
	block->prev = last;
	block->status = STATUS_ALLOC;
	block->size = size;
	if (last)
		last->next = block;
	return block;
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;
	struct block_meta *block;
	size_t size_aligned = ALIGN(size);
	struct block_meta *current =  global_base;

	while (current != NULL) {
		if (current->status == STATUS_FREE && current->next != NULL &&
			current->next->status == STATUS_FREE) {
			struct block_meta *next = current->next;

			current->size += next->size + BLOCK_SIZE;
			current->next = next->next;
			if (current->next != NULL)
				current->next->prev = current;
			else
				current = current->prev;
		}
		current = current->next;
	}

	if (global_base == NULL) {
		prealloc = 0;
		block = request(NULL, size);
		if (block == NULL)
			return NULL;
		global_base = block;
		return PAYLOAD;
	}
	struct block_meta *last = global_base;
	struct block_meta *free = find_free(&last, size);

	if (last->status == STATUS_FREE && last->size < size && free == NULL)
		return expand(last, size);
	if (free == NULL) {
		block = request(last, size);
		if (block == NULL)
			return NULL;
		return PAYLOAD;
	}
	if (free->size >= size_aligned + BLOCK_SIZE + ALIGNMENT) {
		block = free;
		struct block_meta *new = split(&block, size_aligned);

		if (new == NULL)
			return NULL;
		return PAYLOAD;
	}
	free->status = STATUS_ALLOC;
	block = free;
	return PAYLOAD;
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block_ptr = get_block_ptr(ptr);

	if (block_ptr->status == STATUS_MAPPED) {
		if (block_ptr == global_base) {
			global_base = NULL;
			prealloc = 0;
		}
		munmap(block_ptr, ALIGN(block_ptr->size) + BLOCK_SIZE);
		return;
	}
	if (block_ptr->status == STATUS_ALLOC)
		block_ptr->status = STATUS_FREE;
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb <= 0 || size <= 0)
		return NULL;
	size_t total = nmemb * size;
	void *ptr = __calloc(total);

	if (ptr == NULL)
		return NULL;
	memset(ptr, 0, total);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block_ptr = get_block_ptr(ptr);

	if (block_ptr->size >= size)
		return ptr;
	if (size > block_ptr->size && block_ptr->next != NULL &&
		block_ptr->next->status == STATUS_FREE &&
		block_ptr->size + block_ptr->next->size + BLOCK_SIZE >= size) {
		struct block_meta *next = block_ptr->next;

		block_ptr->size += next->size + BLOCK_SIZE;
		block_ptr->next = next->next;
		if (block_ptr->next != NULL)
			block_ptr->next->prev = block_ptr;
		else
			block_ptr = block_ptr->prev;
		return ptr;
	}
	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;
	memcpy(new_ptr, ptr, block_ptr->size + BLOCK_SIZE);
	os_free(ptr);
	return new_ptr;
}
