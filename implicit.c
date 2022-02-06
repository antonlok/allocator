#include "./allocator.h"
#include "./debug_break.h"
#include <limits.h>
#include <string.h>
#include <stdio.h>

#define MINIMUM_SIZE 16
#define HEADER_SIZE 8
#define SIZE_MASK 0xFFFFFFFFFFFFFFF8
#define USED_MASK 0x1
#define DATA_MASK 0x7

typedef unsigned long HEADER;

static void *myheap_start;
static size_t myheap_size;

/* Function: roundup
 * -----------------
 * This function rounds up the given number to the given multiple, which
 * must be a power of 2, and returns the result. Adapted from provided bump.c.
 */
size_t roundup(size_t value, size_t mult) {
    return (value + mult - 1) & ~(mult - 1);
}

/* Function: valid_heap_ptr
 * ----------------
 * This function verifies that a header pointer is within the heap range.
 */
bool valid_heap_ptr(void *candidate) {
    // Two conditions: pointer is at or after the start, and before the end of the system-provided heap space.
    return (candidate >= myheap_start && candidate < (void *)((char *)myheap_start + myheap_size));
}

/* Function: get_hdr
 * ----------------
 * Utility function that takes a header pointer and returns a header object.
 */
HEADER get_hdr(void *hdr_ptr) {
    return *(HEADER *)(hdr_ptr);
}

/* Function: make_hdr
 * ----------------
 * Utility function that takes a allocation size and used status and returns a HEADER object.
 */
HEADER make_hdr(size_t alloc_size, bool in_use) {
    HEADER current_header = alloc_size;
    if (in_use) {
        current_header |= USED_MASK;
    }
    return current_header;
}

/* Function: place_hdr
 * ----------------
 * Utility function that takes a heap location and HEADER and places the HEADER at the location.
 */
void place_hdr(void *new_hdr_loc, HEADER hdr_to_place) {
    *(HEADER *)(new_hdr_loc) = hdr_to_place;
}

/* Function: get_alloc_size
 * ----------------
 * Utility function that takes a header pointer and returns the allocated size.
 */
long get_alloc_size(void *hdr_ptr) {
    return (get_hdr(hdr_ptr) & SIZE_MASK);
}

/* Function: is_used
 * ----------------
 * Utility function that returns true if a header is in use and false if it's free.
 */
bool is_used(void *hdr_ptr) {
    return (get_hdr(hdr_ptr) & USED_MASK);
}

/* Function: flip_status
 * ----------------
 * Utility function that flips the free/used status of a header, given by a pointer.
 */
void flip_status(void *hdr_ptr) {
    HEADER temp_header = get_hdr(hdr_ptr);
    temp_header = temp_header ^ USED_MASK;
    place_hdr(hdr_ptr, temp_header);
}

/* Function: next_hdr
 * ----------------
 * Utility function that takes a header pointer and returns the next header pointer.
 */
void *next_hdr(void *hdr_ptr) {
    return (void *)((char *)hdr_ptr + HEADER_SIZE + (get_hdr(hdr_ptr) & SIZE_MASK));
}

/* Function: jmp_to_hdr
 * ----------------
 * Utility function that takes a block pointer and returns a pointer to the header.
 */
void *jmp_to_hdr(void *blk_ptr) {
    return (void *)((char *)blk_ptr - HEADER_SIZE);
}

/* Function: jmp_to_blk
 * ----------------
 * Utility function that takes a header pointer and returns a pointer to the block.
 */
void *jmp_to_blk(void *hdr_ptr) {
    return (void *)((char *)hdr_ptr + HEADER_SIZE);
}

/* Function: myinit
 * ----------------
 * This function initializes global variables used to store the location of the heap, and the heap size.
 * It also ensures heap size is sufficient for at least one allocation, and makes the starting free header.
 */
bool myinit(void *sys_provided_start, size_t sys_provided_size) {
    myheap_start = sys_provided_start;
    myheap_size = sys_provided_size;

    if (myheap_size < MINIMUM_SIZE || myheap_size > ULONG_MAX) {
        printf("An invalid heap size was requested.");
        return false;
    }

    HEADER initial_header = make_hdr(sys_provided_size - HEADER_SIZE, false);
    place_hdr(myheap_start, initial_header);

    return true;
}

/* Function: mymalloc
 * -----------------
 * This function allocates the requested number of bytes and returns a pointer to the allocated memory.
 */
void *mymalloc(size_t requested_size) {
    size_t rounded_request = roundup(requested_size, ALIGNMENT);
    void *hdr_ptr = myheap_start;

    while (valid_heap_ptr(hdr_ptr)) {

        size_t available_space = get_alloc_size(hdr_ptr);

        // Checks if the current block free, and is large enough to accommodate the requested size.
        if (available_space >= rounded_request && !is_used(hdr_ptr)) {

            // Case 1: Too little extra space in the free block for a new header, so expand the allocation.
            if (available_space - rounded_request < MINIMUM_SIZE) {
                rounded_request = available_space;
                HEADER alloc_header = make_hdr(rounded_request, true);
                place_hdr(hdr_ptr, alloc_header);
                return jmp_to_blk(hdr_ptr);
            }

            // Case 2: Enough extra space in the free block to merit an additional header.
            HEADER alloc_header = make_hdr(rounded_request, true);
            place_hdr(hdr_ptr, alloc_header);
            void *next_header = next_hdr(hdr_ptr);
            HEADER leftover_header = make_hdr(available_space - rounded_request - HEADER_SIZE, false); 
            place_hdr(next_header, leftover_header);
            return jmp_to_blk(hdr_ptr);

        }

        // If the current header is not a sufficiently sized free block, jump to the next header.
        hdr_ptr = next_hdr(hdr_ptr);

    }
    
    // If we exit the for loop with no free block found for the request, we have failed.
    return NULL;
}

/* Function: myfree
 * -----------------
 * This function deallocates the allocation pointed to by the pointer blk_ptr.
 */
void myfree(void *blk_ptr) {
    if (blk_ptr != NULL && valid_heap_ptr(blk_ptr)) {
        void *hdr_ptr = jmp_to_hdr(blk_ptr);
        flip_status(hdr_ptr);
    }
}

/* Function: myrealloc
 * -----------------
 * This function deallocates the old object pointed to by orig_loc and returns a pointer to a 
 * new allocation that has the size specified by new_size. The contents of the new allocation are 
 * the same as those of the old allocation, up to the smaller of the new and old sizes.
 */
void *myrealloc(void *orig_loc, size_t new_size) {
    size_t rounded_new_size = roundup(new_size, ALIGNMENT);
    size_t bytes_to_copy = rounded_new_size;

    if (orig_loc != NULL) {
        void *old_header = jmp_to_hdr(orig_loc);
        size_t previous_alloc_size = get_alloc_size(old_header);
        if (previous_alloc_size <= rounded_new_size) {
            bytes_to_copy = previous_alloc_size;
        }

    }

    void *new_location = mymalloc(rounded_new_size);

    if (orig_loc != NULL) {
        memcpy(new_location, orig_loc, bytes_to_copy);
    }
    
    myfree(orig_loc);

    return new_location;
}

/* Function: validate_heap
 * ----------------
 * This function verifies that the heap is not corrupted.
 * First check: for each header, the three least significant bits contain only the used/free info.
 * Second check: the total count of free bytes, header bytes, and used bytes sums to the segment size.
 */
bool validate_heap() {
    void *hdr_ptr = myheap_start;
    HEADER current_header;

    size_t header_bytes = 0;
    size_t free_bytes = 0;
    size_t used_bytes = 0;
    size_t block_number = 0;

    while (valid_heap_ptr(hdr_ptr)) {
        current_header = get_hdr(hdr_ptr);
        if (((current_header & DATA_MASK) != 0) && ((current_header & DATA_MASK) != 1)) {
            printf("Block #%lu has an issue with the three LSBs.", block_number);
            return false;
        }

        header_bytes += HEADER_SIZE;

        if (current_header & USED_MASK) {
            used_bytes += get_alloc_size(hdr_ptr);
        }
        else {
            free_bytes += get_alloc_size(hdr_ptr);
        }

        hdr_ptr = next_hdr(hdr_ptr);
        block_number += 1;
    }

    if (free_bytes + used_bytes + header_bytes != myheap_size) {
        printf("\nThe three types of bytes do not sum to the total allocation.");
        printf("\nThe three types of bytes sum to %lu, while the allocation is %lu.", free_bytes + used_bytes + header_bytes, myheap_size);
        printf("\nFree byte count: %lu.", free_bytes);
        printf("\nUsed byte count: %lu.", used_bytes);
        printf("\nHeader byte count: %lu.", header_bytes);
        return false;
    }

    return true;
}

/* Function: dump_heap
 * ----------------
 * Utility function that prints the bounds of the heap, and the bounds, status, and size of every block in the heap.
 */
void dump_heap() {
    printf("The allocated heap segment starts at address %p, and ends at %p.\n", myheap_start, (char *)myheap_start + myheap_size);

    void *hdr_ptr = myheap_start;
    size_t block_counter = 0;
    
    while (valid_heap_ptr(hdr_ptr)) {
        size_t alloc_size = get_alloc_size(hdr_ptr);
        bool alloc_used = is_used(hdr_ptr);
        if (alloc_used) {
            printf("Block #%lu is a USED alloc of size %lu, starting at address %p and ending at address %p.\n", block_counter, alloc_size, (char *)hdr_ptr + HEADER_SIZE, (char *)hdr_ptr + HEADER_SIZE + alloc_size);
        }
        else {
            printf("Block #%lu is a FREE alloc of size %lu, starting at address %p and ending at address %p.\n", block_counter, alloc_size, (char *)hdr_ptr + HEADER_SIZE, (char *)hdr_ptr + HEADER_SIZE + alloc_size);
        }
        block_counter += 1;
        hdr_ptr = next_hdr(hdr_ptr);
    }
}