Malloc Library Design:

I have implemented buddy system algorithm for the malloc library.

Key Design Decisions:

1.) Each Arena has an Arena Header which maintains bins for that arena. I maintain 9 Bins. Minimum Bin size is 32 bytes as the block_header size is 16bytes 
2.) I maintain 1 bin each for 32,64,128,256,512,1024,2048,4096 block sizes and 1 bin for all other blocks > 4096
3.) Arena can have multiple heap blocks. Only the 1st heap in the arena will have arena header and heap header. Rest of the heaps will have only heap_header
4.) To satisfy memory requests < 4096 bytes, heap will be allocated using sbrk() system call of size _sys_page_size.
5.) To satisfy memory requests > 4096 bytes, heap will be allocated using mmap() system call of size requested rounded off to next power of 2.
6.) Max no. of arenas are limited to no. of processors in the system. By default I will have a minimum of 4 thread arenas.
7.) I have thread exit handlers which updates the arenas used by the respective thread. I will remove all the unused mmap() blocks of that arena in thread_exit handlers.
8.) Once maximum arenas are reached, for the new threads the arena are allocated based on no of threads associated with the thread arenas. The least one is allotted.

Improvements:

1.) Currently I have linked list data structure in the bins and this will result in O(n). This can be optimized to O(log(n)) using a tree.
2.) Garbage Collection should be introduced to remove unused heap memory. For this, the code should be adapted to use sbrk() only for main thread arena and mmap() for all the thread arenas so that the heap can be released.

Extra Credit Implementation:

1.) I have implemented Buddy System Algorithm for the blocks less than 4096 bytes
2.) I have implemented a malloc hook for initialization.
3.) Memory Consistency Check - Not implemented.