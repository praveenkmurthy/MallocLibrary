/*
 * malloc.c
 *
 *  Created on: Feb 27, 2016
 *      Author: Praveen
 */

#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <stddef.h>

#define MIN_THREAD_ARENA 4
#define HEAP_PAGE_SIZE 4096
#define MAX_BINS 9
#define MIN_HEAP_BLOCK_SIZE_ORDER 5
#define MAX_HEAP_BLOCK_SIZE_ORDER 12
#define NOT_ALLOCATED 0
#define ALLOCATED 1
#define MMAPED 1
#define NOT_MMAPED 0
#define MMAP_BIN 8
#define SUCCESS 0
#define FAILURE 1
#define BASE 2

#define DATA_OFFSET offsetof(block_header_t, block_data)
#define BLOCK_HEADER_PTR( ptr ) ( (char*)ptr - DATA_OFFSET )
#define SIZE_TO_ORDER(size) ( ceil( (log(size) / log(BASE) )) )
#define INITIALIZE_PTHREAD_MUTEX(mutex) ( memset(mutex, 0, sizeof(pthread_mutex_t) ))
#define INITIALIZE_BIN_COUNTS(bin_ptr) ( memset(bin_ptr, 0, sizeof(uint16_t) * MAX_BINS) )
#define ORDER_TO_BIN_INDEX(order) (order - MIN_HEAP_BLOCK_SIZE_ORDER)

typedef struct _block_header {
	uint8_t allocated;
	uint8_t mmaped;
	uint8_t block_size;
	void* block_base_address;
	union {
		struct _block_header* next_block_ptr;
		void *data[0];
	} block_data;
} block_header_t;

typedef enum {
	USED = 0, UNUSED
} arena_status_t;

typedef struct _arena_header {
	pthread_mutex_t arena_lock;
	uint16_t no_of_heaps;
	uint8_t no_of_threads;
	arena_status_t arena_status;
	block_header_t* bins[MAX_BINS];
	size_t bin_counts[MAX_BINS];
	size_t total_alloc_req;
	size_t total_free_req;
	struct _arena_header* next_arena;
} arena_header_t;

typedef struct _heap_header {
	struct _heap_header* next_heap_ptr;
	size_t heap_size;
	uint8_t heap_mmaped;
	arena_header_t* arena_ptr;
	void* heap_base_addr;
} heap_header_t;

typedef struct __malloc_metadata {
	heap_header_t heap_ptr;
	arena_header_t arena_ptr;
} malloc_metadata;

#define HEAP_TO_ARENA_PTR( heap_ptr ) ( ((char*) heap_ptr) + sizeof(heap_header_t) )
#define HEAP_TO_BLOCK_PTR( heap_ptr ) ( ((char*) heap_ptr) + sizeof(heap_header_t) )
#define ARENA_TO_HEAP_PTR( arena_ptr ) ( ((char*) arena_ptr) - sizeof(heap_header_t) )
#define ARENA_TO_BLOCK_PTR( arena_ptr ) ( ((char*) arena_ptr) + sizeof(arena_header_t) )
#define BLOCK_TO_ARENA_PTR( block_ptr ) ( ((char*) block_ptr) - sizeof(arena_header_t) )
#define MMAP_BLOCK_TO_HEAP_PTR( block_ptr ) ( ((char*) block_ptr) - sizeof(heap_header_t) )

static malloc_metadata main_thread_metadata = { 0 };
static int no_of_arenas = 1;
static int no_of_processors = 1;
static long sys_page_size = HEAP_PAGE_SIZE;
static bool malloc_initialized = 0;
static __thread arena_header_t* ts_arena_ptr;
static __thread pthread_key_t arena_key;
static pthread_mutex_t malloc_thread_init_lock = PTHREAD_MUTEX_INITIALIZER;
arena_header_t* last_used_arena = &main_thread_metadata.arena_ptr;

void sort_and_add(arena_header_t* ar_ptr, uint8_t bin_index,
		block_header_t* block_to_insert);

static void* initialize_malloc_lib(size_t size, const void* caller);
void release_mmap_blocks(arena_header_t* ar_ptr, block_header_t* block_ptr);

typedef void *(*__hook)(size_t __size, const void *);
__hook        __malloc_hook = (__hook ) initialize_malloc_lib;

extern void *malloc(size_t size);

typedef void (*pthread_atfork_handlers)(void);
typedef void (*thread_exit_handlers)(void*);

long get_total_arena_size(heap_header_t* heap_itr){

	long ret_val = 0;

	while(heap_itr != NULL){
		ret_val += heap_itr->heap_size;
		heap_itr = heap_itr->next_heap_ptr;
	}

	return ret_val;
}

void print_malloc_stats() {

	arena_header_t* arena_ptr = &main_thread_metadata.arena_ptr;
	int arena_index = 1;
	do {
		printf("============================Arena Info %d=============================\n", arena_index++);
		printf("\t Total Size of Arena        : %ld KB\n", (get_total_arena_size((heap_header_t*) ARENA_TO_HEAP_PTR(arena_ptr)) / 1024) );
		printf("\t Total Bins                 : %d\n", MAX_BINS);
		printf("\t Total Allocation Requests  : %ld\n", arena_ptr->total_alloc_req);
		printf("\t Total Free Requests        : %ld\n", arena_ptr->total_free_req);

		int i;
		for (i = 0; i < MAX_BINS; i++){
			printf("\t Bin Index %d\n", i);
			printf("\t\t Total Number of Free Blocks		: %d\n", arena_ptr->bin_counts[i] );
		}
		arena_ptr = arena_ptr->next_arena;
	} while (arena_ptr != NULL);
}

void acquire_all_locks() {

	pthread_mutex_lock(&malloc_thread_init_lock);

	arena_header_t* arena_ptr = &main_thread_metadata.arena_ptr;

	while (arena_ptr) {
		pthread_mutex_lock(&arena_ptr->arena_lock);
		arena_ptr = arena_ptr->next_arena;
	}
}

void release_all_locks() {

	arena_header_t* arena_ptr = &main_thread_metadata.arena_ptr;

	while (arena_ptr) {
		pthread_mutex_unlock(&arena_ptr->arena_lock);
		arena_ptr = arena_ptr->next_arena;
	}

	pthread_mutex_unlock(&malloc_thread_init_lock);

}

void pthread_atfork_prepare(void) {
	acquire_all_locks();
}

void pthread_atfork_parent(void) {
	release_all_locks();
}

void pthread_atfork_child(void) {
	release_all_locks();
}

void thread_destructor(void* ptr) {
	if(ptr == NULL)
		return;

	arena_header_t* ar_ptr = ptr;

	pthread_mutex_lock(&malloc_thread_init_lock);
	pthread_mutex_lock(&ar_ptr->arena_lock);

	ar_ptr->no_of_threads--;

	block_header_t* block_itr = ar_ptr->bins[MMAP_BIN];
	while (block_itr != NULL) {
		block_header_t* next_block_ptr = block_itr->block_data.next_block_ptr;

		if (block_itr->allocated == NOT_ALLOCATED) {
			release_mmap_blocks(ar_ptr, block_itr);
			ar_ptr->bin_counts[MMAP_BIN]--;
		}

		block_itr = next_block_ptr;
	}

	if (ar_ptr->bin_counts[MMAP_BIN] == 0) {
		ar_ptr->bins[MMAP_BIN] = NULL;
	}

	if (ar_ptr->no_of_threads == 0)
		ar_ptr->arena_status = UNUSED;

	pthread_mutex_unlock(&ar_ptr->arena_lock);
	pthread_mutex_unlock(&malloc_thread_init_lock);
}

static void* initialize_malloc_lib(size_t size, const void* caller) {
	if (pthread_atfork(pthread_atfork_prepare, pthread_atfork_parent,
			pthread_atfork_child))
		return NULL;

	if (initialize_main_arena())
		return NULL;

	__malloc_hook = NULL;

	return malloc(size);
}

int initialize_main_arena() {
	int ret_val = SUCCESS;

	if (malloc_initialized)
		return ret_val;

	if ((sys_page_size = sysconf(_SC_PAGESIZE)) == -1)
		sys_page_size = HEAP_PAGE_SIZE;

	if ((no_of_processors = sysconf(_SC_NPROCESSORS_ONLN)) == -1)
		no_of_processors = 1;

	if( no_of_processors < MIN_THREAD_ARENA )
		no_of_processors = MIN_THREAD_ARENA;

	ts_arena_ptr = &main_thread_metadata.arena_ptr;
	INITIALIZE_PTHREAD_MUTEX(&ts_arena_ptr->arena_lock);
	INITIALIZE_BIN_COUNTS(&ts_arena_ptr->bin_counts);
	ts_arena_ptr->arena_status = USED;
	ts_arena_ptr->no_of_heaps = 1;
	ts_arena_ptr->no_of_threads = 1;
	ts_arena_ptr->next_arena = NULL;
	ts_arena_ptr->total_alloc_req = 0;
	ts_arena_ptr->total_free_req = 0;

	pthread_key_create(&arena_key, thread_destructor);
	pthread_setspecific(arena_key, (void *) ts_arena_ptr);

	block_header_t* block_ptr = NULL;
	if ((block_ptr = (block_header_t*) sbrk(sys_page_size)) == NULL) {
		errno = ENOMEM;
		ret_val = FAILURE;
		return ret_val;
	}

	block_ptr->allocated = NOT_ALLOCATED;
	block_ptr->mmaped = NOT_MMAPED;
	block_ptr->block_size = MAX_HEAP_BLOCK_SIZE_ORDER;
	block_ptr->block_data.next_block_ptr = NULL;
	block_ptr->block_base_address = block_ptr;
	sort_and_add(ts_arena_ptr, ORDER_TO_BIN_INDEX(MAX_HEAP_BLOCK_SIZE_ORDER),
			block_ptr);

	heap_header_t* heap_ptr = &main_thread_metadata.heap_ptr;
	heap_ptr->arena_ptr = ts_arena_ptr;
	heap_ptr->heap_size = sys_page_size;
	heap_ptr->heap_mmaped = NOT_MMAPED;
	heap_ptr->next_heap_ptr = NULL;
	heap_ptr->heap_base_addr = block_ptr;

	malloc_initialized = 1;
	return ret_val;
}

arena_header_t* get_unused_arena_if_any(){

	arena_header_t* arena_itr = &main_thread_metadata.arena_ptr;

	while( arena_itr != NULL ){
		if( arena_itr->arena_status == UNUSED ){
			return arena_itr;
		}
		arena_itr = arena_itr->next_arena;
	}

	return NULL;
}

arena_header_t* find_arena_based_on_least_threads() {

	arena_header_t* ret_arena_ptr = &main_thread_metadata.arena_ptr;
	arena_header_t* arena_itr = &main_thread_metadata.arena_ptr;

	while (arena_itr != NULL) {
		if (arena_itr->no_of_threads < ret_arena_ptr->no_of_threads) {
			ret_arena_ptr = arena_itr;
		}
		arena_itr = arena_itr->next_arena;
	}

	ret_arena_ptr->no_of_threads++;
	return ret_arena_ptr;
}

void link_arena(arena_header_t* arena_ptr) {
	arena_header_t* arena_itr = &main_thread_metadata.arena_ptr;
	while (arena_itr->next_arena != NULL) {
		arena_itr = arena_itr->next_arena;
	}
	arena_ptr->next_arena = NULL;
	arena_itr->next_arena = arena_ptr;
}

int initialize_thread_arena() {
	pthread_mutex_lock(&malloc_thread_init_lock);

	if (no_of_arenas == no_of_processors) {
		if ((ts_arena_ptr = get_unused_arena_if_any()) == NULL){
			ts_arena_ptr = find_arena_based_on_least_threads();
		}

		pthread_key_create(&arena_key, thread_destructor);
		pthread_setspecific(arena_key, (void *) ts_arena_ptr);

		pthread_mutex_unlock(&malloc_thread_init_lock);
		return SUCCESS;
	}

	int ret_val = SUCCESS;
	heap_header_t* heap_ptr = NULL;
	arena_header_t* arena_ptr = NULL;

	uint16_t heap_size = sys_page_size + sizeof(arena_header_t)
			+ sizeof(heap_header_t);

	if ((heap_ptr = (heap_header_t*) sbrk(heap_size)) == NULL) {
		errno = ENOMEM;
		ret_val = FAILURE;
		pthread_mutex_unlock(&malloc_thread_init_lock);
		return ret_val;
	}

	arena_ptr = (arena_header_t*) HEAP_TO_ARENA_PTR(heap_ptr);
	INITIALIZE_PTHREAD_MUTEX(&arena_ptr->arena_lock);
	INITIALIZE_BIN_COUNTS(&arena_ptr->bin_counts);
	arena_ptr->no_of_heaps = 1;
	arena_ptr->next_arena = NULL;
	arena_ptr->arena_status = USED;
	arena_ptr->no_of_threads = 1;
	arena_ptr->total_alloc_req = 0;
	arena_ptr->total_free_req = 0;

	link_arena(arena_ptr);

	pthread_key_create(&arena_key, thread_destructor);
	pthread_setspecific(arena_key, (void *) ts_arena_ptr);

	heap_ptr->arena_ptr = arena_ptr;
	heap_ptr->heap_size = heap_size;
	heap_ptr->heap_mmaped = NOT_MMAPED;
	heap_ptr->next_heap_ptr = NULL;
	heap_ptr->heap_base_addr = heap_ptr;

	block_header_t* block_ptr = (block_header_t*) ARENA_TO_BLOCK_PTR(arena_ptr);
	block_ptr->allocated = NOT_ALLOCATED;
	block_ptr->mmaped = NOT_MMAPED;
	block_ptr->block_size = MAX_HEAP_BLOCK_SIZE_ORDER;
	block_ptr->block_data.next_block_ptr = NULL;
	block_ptr->block_base_address = block_ptr;
	sort_and_add(arena_ptr, ORDER_TO_BIN_INDEX(MAX_HEAP_BLOCK_SIZE_ORDER),
			block_ptr);

	ts_arena_ptr = arena_ptr;
	no_of_arenas++;
	pthread_mutex_unlock(&malloc_thread_init_lock);

	return ret_val;
}

void sort_and_add(arena_header_t* ar_ptr, uint8_t bin_index,
		block_header_t* block_to_insert) {

	ar_ptr->bin_counts[bin_index]++;
	block_to_insert->block_data.next_block_ptr = NULL;

	if (ar_ptr->bins[bin_index] == NULL) {
		ar_ptr->bins[bin_index] = block_to_insert;
	} else if (block_to_insert < ar_ptr->bins[bin_index]) {
		block_to_insert->block_data.next_block_ptr = ar_ptr->bins[bin_index];
		ar_ptr->bins[bin_index] = block_to_insert;
	} else {
		block_header_t* itr = ar_ptr->bins[bin_index], *prev_block = NULL;

		while (itr != NULL && block_to_insert > itr) {
			prev_block = itr;
			itr = itr->block_data.next_block_ptr;
		}

		if (itr == NULL) {
			block_to_insert->block_data.next_block_ptr = NULL;
			prev_block->block_data.next_block_ptr = block_to_insert;
		} else {
			block_to_insert->block_data.next_block_ptr =
					prev_block->block_data.next_block_ptr;
			prev_block->block_data.next_block_ptr = block_to_insert;
		}
	}
}

void sort_and_add_block_size(arena_header_t* ar_ptr, uint8_t bin_index,
		block_header_t* block_to_insert) {

	ar_ptr->bin_counts[bin_index]++;
	block_to_insert->block_data.next_block_ptr = NULL;

	if (ar_ptr->bins[bin_index] == NULL) {
		ar_ptr->bins[bin_index] = block_to_insert;
	} else if (block_to_insert->block_size
			<= ar_ptr->bins[bin_index]->block_size) {
		block_to_insert->block_data.next_block_ptr = ar_ptr->bins[bin_index];
		ar_ptr->bins[bin_index] = block_to_insert;
	} else {
		block_header_t* itr = ar_ptr->bins[bin_index], *prev_block = NULL;

		while (itr != NULL && block_to_insert->block_size > itr->block_size) {
			prev_block = itr;
			itr = itr->block_data.next_block_ptr;
		}

		if (itr == NULL) {
			block_to_insert->block_data.next_block_ptr = NULL;
			prev_block->block_data.next_block_ptr = block_to_insert;
		} else {
			block_to_insert->block_data.next_block_ptr =
					prev_block->block_data.next_block_ptr;
			prev_block->block_data.next_block_ptr = block_to_insert;
		}
	}
}

void* divide_blocks_and_add_to_bins(arena_header_t* ar_ptr, uint8_t bin_index,
		block_header_t* mem_block_ptr, int block_size_order) {
	int size = pow(2, block_size_order);
	void *mem_block_1 = mem_block_ptr;
	void *mem_block_2 = (((char*) mem_block_ptr) + (size / 2));

	block_header_t* block_hdr = NULL;

	block_hdr = (block_header_t*) mem_block_1;
	block_hdr->allocated = NOT_ALLOCATED;
	block_hdr->mmaped = NOT_MMAPED;
	block_hdr->block_size = block_size_order - 1;
	block_hdr->block_base_address = mem_block_ptr->block_base_address;

	block_hdr = (block_header_t*) mem_block_2;
	block_hdr->allocated = NOT_ALLOCATED;
	block_hdr->mmaped = NOT_MMAPED;
	block_hdr->block_size = block_size_order - 1;
	block_hdr->block_base_address = mem_block_ptr->block_base_address;

	sort_and_add(ar_ptr, bin_index, mem_block_1);
	return mem_block_2;

}

block_header_t* find_free_block(arena_header_t* ar_ptr, uint8_t bin_index) {

	if (bin_index == (MAX_BINS - 1))
		return NULL;

	block_header_t *ret_ptr = NULL;

	if (ar_ptr->bins[bin_index] != NULL) {
		ret_ptr = ar_ptr->bins[bin_index];
		ar_ptr->bins[bin_index] = ret_ptr->block_data.next_block_ptr;
		ar_ptr->bin_counts[bin_index]--;
	} else {
		block_header_t* block = (block_header_t*) find_free_block(ar_ptr,
				bin_index + 1);

		if (block != NULL) {
			ret_ptr = divide_blocks_and_add_to_bins(ar_ptr, bin_index, block,
					block->block_size);
		}
	}

	return ret_ptr;
}

block_header_t* find_free_mmap_block(arena_header_t* ar_ptr, uint8_t size_order) {

	block_header_t* free_list_itr = ar_ptr->bins[MMAP_BIN], *ret_ptr = NULL,
			*prev_block = NULL;

	while (free_list_itr != NULL && free_list_itr->block_size < size_order) {
		prev_block = free_list_itr;
		free_list_itr = free_list_itr->block_data.next_block_ptr;
	}

	if (free_list_itr != NULL && prev_block == NULL) {
		ret_ptr = free_list_itr;
		ar_ptr->bins[MMAP_BIN] = ret_ptr->block_data.next_block_ptr;
		ar_ptr->bin_counts[MMAP_BIN]--;
	} else if (free_list_itr != NULL && prev_block != NULL) {
		ret_ptr = free_list_itr;
		prev_block->block_data.next_block_ptr =
				ret_ptr->block_data.next_block_ptr;
		ar_ptr->bin_counts[MMAP_BIN]--;
	}

	return ret_ptr;

}

void link_to_existing_heap(arena_header_t* ar_ptr, heap_header_t* heap_ptr) {
	heap_header_t* main_heap_ptr = (heap_header_t*) ARENA_TO_HEAP_PTR(ar_ptr);
	heap_ptr->next_heap_ptr = main_heap_ptr->next_heap_ptr;
	main_heap_ptr->next_heap_ptr = heap_ptr;
	ar_ptr->no_of_heaps++;
}

void* allocate_new_block(arena_header_t* ar_ptr, size_t size_order) {

	block_header_t* new_block = NULL;

	heap_header_t* heap_ptr = NULL;
	size_t heap_size = sys_page_size + sizeof(heap_header_t);

	if ((heap_ptr = (heap_header_t*) sbrk(heap_size)) == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	heap_ptr->arena_ptr = ar_ptr;
	heap_ptr->heap_mmaped = NOT_MMAPED;
	heap_ptr->heap_size = heap_size;
	heap_ptr->next_heap_ptr = NULL;
	heap_ptr->heap_base_addr = heap_ptr;

	link_to_existing_heap(ar_ptr, heap_ptr);

	new_block = (block_header_t*) HEAP_TO_BLOCK_PTR(heap_ptr);
	new_block->allocated = NOT_ALLOCATED;
	new_block->block_size = MAX_HEAP_BLOCK_SIZE_ORDER;
	new_block->block_data.next_block_ptr = NULL;
	new_block->block_base_address = new_block;

	sort_and_add(ar_ptr, ORDER_TO_BIN_INDEX(MAX_HEAP_BLOCK_SIZE_ORDER),
			new_block);

	return find_free_block(ar_ptr, size_order - MIN_HEAP_BLOCK_SIZE_ORDER);
}

void* mmap_and_allocate(arena_header_t* ar_ptr, size_t size) {

	int heap_size = pow(2, SIZE_TO_ORDER(size)) + sizeof(heap_header_t);

	block_header_t* block_ptr = NULL;
	heap_header_t* heap_ptr = NULL;

	if ((heap_ptr = (heap_header_t*) mmap(NULL, heap_size,
	PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
		errno = ENOMEM;
		return NULL;
	}

	heap_ptr->arena_ptr = ar_ptr;
	heap_ptr->heap_mmaped = MMAPED;
	heap_ptr->heap_size = heap_size;
	heap_ptr->next_heap_ptr = NULL;
	heap_ptr->heap_base_addr = heap_ptr;

	link_to_existing_heap(ar_ptr, heap_ptr);

	block_ptr = (block_header_t*) HEAP_TO_BLOCK_PTR(heap_ptr);
	block_ptr->mmaped = MMAPED;
	block_ptr->block_size = SIZE_TO_ORDER(size);
	block_ptr->block_base_address = block_ptr;
	block_ptr->block_data.next_block_ptr = NULL;

	return block_ptr;

}

void* __lib_malloc(size_t size) {

	block_header_t* ret_addr = NULL;

	__hook lib_hook = __malloc_hook;

	if (lib_hook != NULL) {
		return (*lib_hook)(size, __builtin_return_address(0));
	}

	if (ts_arena_ptr == NULL && initialize_thread_arena()) {
		errno = ENOMEM;
		return NULL;
	}

	pthread_mutex_lock(&ts_arena_ptr->arena_lock);
	ts_arena_ptr->total_alloc_req++;

	uint8_t size_order = SIZE_TO_ORDER(size + DATA_OFFSET);
	if (size_order < MIN_HEAP_BLOCK_SIZE_ORDER)
		size_order = MIN_HEAP_BLOCK_SIZE_ORDER;

	if (size_order <= MAX_HEAP_BLOCK_SIZE_ORDER) {
		if ((ret_addr = find_free_block(ts_arena_ptr,
				(size_order - MIN_HEAP_BLOCK_SIZE_ORDER))) != NULL) {
			ret_addr->allocated = ALLOCATED;
			ret_addr = (void*) &ret_addr->block_data.data;
		} else if ((ret_addr = allocate_new_block(ts_arena_ptr, size_order))
				!= NULL) {
			ret_addr->allocated = ALLOCATED;
			ret_addr = (void*) &ret_addr->block_data.data;
		}
	} else {
		if ((ret_addr = find_free_mmap_block(ts_arena_ptr, size_order)) != NULL) {
			ret_addr->allocated = ALLOCATED;
			ret_addr = (void*) &ret_addr->block_data.data;
		} else if ((ret_addr = mmap_and_allocate(ts_arena_ptr,
				(size + DATA_OFFSET))) != NULL) {
			ret_addr->allocated = ALLOCATED;
			ret_addr = (void*) &ret_addr->block_data.data;
		}
	}

	pthread_mutex_unlock(&ts_arena_ptr->arena_lock);

	return (void*) ret_addr;
}

block_header_t* get_buddy_block_address(block_header_t* block) {

	size_t block_size = pow(2, block->block_size);
	uint8_t block_index = ((block->block_base_address - (void*) block)
			/ block_size);

	if (block_index % 2)
		return (block_header_t*) ((char*) block - block_size);
	else
		return (block_header_t*) ((char*) block + block_size);
}

void merge_blocks_if_possible(arena_header_t* ar_ptr, block_header_t* block,
		uint8_t bin_index) {

	if (bin_index >= MAX_BINS - 2) {
		sort_and_add(ar_ptr, bin_index, block);
		return;
	}

	block_header_t* block_itr = ar_ptr->bins[bin_index], *prev_block = NULL;
	block_header_t* buddy_addr = get_buddy_block_address(block);

	if (buddy_addr->allocated) {
		sort_and_add(ar_ptr, bin_index, block);
		return;
	}

	while (block_itr && block_itr != buddy_addr) {
		prev_block = block_itr;
		block_itr = block_itr->block_data.next_block_ptr;
	}

	if (block_itr != NULL) {
		if (prev_block == NULL)
			ar_ptr->bins[bin_index] = block_itr->block_data.next_block_ptr;
		else
			prev_block->block_data.next_block_ptr =
					block_itr->block_data.next_block_ptr;

		ar_ptr->bin_counts[bin_index]--;

		if (block < buddy_addr)
			block->block_size++;
		else {
			block = buddy_addr;
			block->block_size++;
		}

		merge_blocks_if_possible(ar_ptr, block, (bin_index + 1));
	} else {
		sort_and_add(ar_ptr, bin_index, block);
	}
}

void unlink_from_heap_list(arena_header_t* ar_ptr, heap_header_t* heap_ptr) {

	heap_header_t* heap_itr = (heap_header_t*) ARENA_TO_HEAP_PTR(ar_ptr);
	heap_header_t* prev_heap_ptr = (heap_header_t*) heap_itr;

	heap_itr = heap_itr->next_heap_ptr;
	while (heap_itr != NULL
			&& heap_itr->heap_base_addr != heap_ptr->heap_base_addr) {
		prev_heap_ptr = (heap_header_t*) heap_itr;
		heap_itr = heap_itr->next_heap_ptr;
	}

	if (heap_itr != NULL) {
		prev_heap_ptr->next_heap_ptr = heap_itr->next_heap_ptr;
		ar_ptr->no_of_heaps--;
	}
}

void release_mmap_blocks(arena_header_t* ar_ptr, block_header_t* block_ptr) {

	heap_header_t* heap_ptr = (heap_header_t*) MMAP_BLOCK_TO_HEAP_PTR(block_ptr);
	unlink_from_heap_list(ar_ptr, heap_ptr);
	munmap(heap_ptr->heap_base_addr, heap_ptr->heap_size);

}

void release_block_to_bin(arena_header_t* ar_ptr, block_header_t* block_ptr) {
	block_header_t** free_list_itr = NULL;
	size_t size_order = block_ptr->block_size;
	uint8_t bin_index = -1;

	block_ptr->allocated = NOT_ALLOCATED;
	if (block_ptr->mmaped && block_ptr->block_size <= 15) {
		bin_index = MMAP_BIN;
		sort_and_add_block_size(ar_ptr, MMAP_BIN, block_ptr);
	} else if (block_ptr->mmaped) {
		release_mmap_blocks(ar_ptr, block_ptr);
	} else {
		bin_index = size_order - MIN_HEAP_BLOCK_SIZE_ORDER;
		merge_blocks_if_possible(ar_ptr, block_ptr, bin_index);
	}

}

bool is_valid_address(arena_header_t* ar_ptr, void* mem_ptr) {
	bool ret_val = true;

	if (mem_ptr == NULL)
		ret_val = false;
	else {
		heap_header_t* heap_ptr = (heap_header_t*) ARENA_TO_HEAP_PTR(ar_ptr);
		ret_val = false;
		while (heap_ptr) {
			if ((mem_ptr >= (void*) heap_ptr->heap_base_addr)
					&& (mem_ptr
							<= (void*) (((char*) heap_ptr->heap_base_addr)
									+ heap_ptr->heap_size))) {
				ret_val = true;
				break;
			}
			heap_ptr = heap_ptr->next_heap_ptr;
		}
	}

	return ret_val;
}

void __lib_free(void* mem_ptr) {
	block_header_t* block_ptr = NULL;

	if (ts_arena_ptr == NULL) {
		return;
	}

	if (!is_valid_address(ts_arena_ptr, mem_ptr))
		return;

	block_ptr = (block_header_t*) BLOCK_HEADER_PTR( mem_ptr );

	pthread_mutex_lock(&ts_arena_ptr->arena_lock);
	ts_arena_ptr->total_free_req++;

	release_block_to_bin(ts_arena_ptr, block_ptr);

	pthread_mutex_unlock(&ts_arena_ptr->arena_lock);

}

void *__lib_calloc(size_t nmemb, size_t size) {

	block_header_t* block_ptr = NULL;
	void* ret_ptr = __lib_malloc(nmemb * size);

	if (ret_ptr == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	block_ptr = (block_header_t*) BLOCK_HEADER_PTR( ret_ptr );
	int block_size = (pow(2, block_ptr->block_size) - DATA_OFFSET);
	memset(&block_ptr->block_data.data, 0, block_size);

	return ret_ptr;
}

void *__lib_realloc(void *ptr, size_t size) {

	void* ret_ptr = NULL;

	if (size != 0)
		ret_ptr = __lib_malloc(size);
	else if (ptr != NULL && size == 0) {
		__lib_free(ptr);
		return NULL;
	}

	if (ptr == NULL || !is_valid_address(ts_arena_ptr, ptr))
		return ret_ptr;

	pthread_mutex_lock(&ts_arena_ptr->arena_lock);

	block_header_t* block_ptr = NULL, *prev_block_ptr =
			(block_header_t*) BLOCK_HEADER_PTR(ptr);

	block_ptr = (block_header_t*) BLOCK_HEADER_PTR(ret_ptr);

	size_t copy_size =
			(prev_block_ptr->block_size > block_ptr->block_size) ?
					block_ptr->block_size : prev_block_ptr->block_size;

	copy_size = pow(2, copy_size) - DATA_OFFSET;

	memset(&block_ptr->block_data.data, 0, copy_size);
	memcpy(&block_ptr->block_data.data, &prev_block_ptr->block_data.data,
			copy_size);

	pthread_mutex_unlock(&ts_arena_ptr->arena_lock);

	__lib_free(ptr);

	return ret_ptr;

}

void* malloc(size_t size) __attribute__((weak, alias ("__lib_malloc")));
void* free(void* mem_ptr) __attribute__((weak, alias ("__lib_free")));
void *calloc(size_t nmemb, size_t size) __attribute__((weak, alias("__lib_calloc")));
void *realloc(void *ptr, size_t size) __attribute__((weak, alias("__lib_realloc")));
void malloc_stats() __attribute__((weak, alias("print_malloc_stats")));
