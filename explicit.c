#include "./allocator.h"
#include "./debug_break.h"
#include <limits.h>
#include <string.h>
#include <stdio.h>

#define MINIMUM_SIZE 24
#define HEADER_SIZE 8
#define SIZE_MASK 0xFFFFFFFFFFFFFFF8
#define USED_MASK 0x1
#define DATA_MASK 0x7

typedef unsigned long HEADER;

static void *myheap_start;
static size_t myheap_size;
static void *top_free_list;

/* Function: roundup
 * ----------------
 * Utility function that rounds value up to the nearest multiple of mult. Mult must be a multiple of 2.
 * Adapted from code provided in bump.c.
 */
size_t roundup(size_t value, size_t mult) {
    return (value + mult - 1) & ~(mult - 1);
}

/* Function: valid_heap_ptr
 * ----------------
 * Utility function that checks that a pointer is a valid pointer to our heap segment.
 */
bool valid_heap_ptr(void *candidate) {
    bool non_void = (candidate != NULL);
    bool in_range = (candidate >= myheap_start && candidate < (void *)((char *)myheap_start + myheap_size));
    return (non_void && in_range);
}

/* Function: place_hdr
 * ----------------
 * Utility function that places a HEADER at the specified location in the heap segment.
 */
void place_hdr(void *new_hdr_loc, HEADER hdr_to_place) {
    *(HEADER *)(new_hdr_loc) = hdr_to_place;
}

/* Function: get_hdr
 * ----------------
 * Utility function that retrieves the HEADER object stored at a memory location.
 */
HEADER get_hdr(void *hdr_ptr) {
    return *(HEADER *)(hdr_ptr);
}

/* Function: make_hdr
 * ----------------
 * Utility function that creates a HEADER object from an allocation size and a boolean representing in-use status.
 */
HEADER make_hdr(size_t alloc_size, bool in_use) {
    HEADER new_header = alloc_size;
    if (in_use) {
        new_header |= USED_MASK;
    }
    return new_header;
}

/* Function: next_hdr
 * ----------------
 * Utility function that steps to the next header pointer in the stack after the given header pointer.
 */
void *next_hdr(void *hdr_ptr) {
    return (void *)((char *)hdr_ptr + HEADER_SIZE + (get_hdr(hdr_ptr) & SIZE_MASK));
}

/* Function: get_alloc_size
 * ----------------
 * Utility function that gets the size of an allocation in the heap segment pointed to by the header pointer.
 */
size_t get_alloc_size(void *hdr_ptr) {
    return (get_hdr(hdr_ptr) & SIZE_MASK);
}

/* Function: is_used
 * ----------------
 * Utility function that returns whether an allocation (provided via heap pointer) is in use or not.
 */
bool is_used(void *hdr_ptr) {
    return (get_hdr(hdr_ptr) & USED_MASK);
}

/* Function: flip_status
 * ----------------
 * Utility function that changes the in-use status of the HEADER (provided via heap pointer).
 */
void flip_status(void *hdr_ptr) {
    HEADER temp_header = get_hdr(hdr_ptr);
    temp_header = temp_header ^ USED_MASK;
    place_hdr(hdr_ptr, temp_header);
}

/* Function: jmp_to_blk
 * ----------------
 * Utility function that returns a pointer to the data segment given a pointer to the HEADER.
 */
void *jmp_to_blk(void *hdr_ptr) {
    return (void *)((char *)hdr_ptr + HEADER_SIZE);
}

/* Function: jmp_to_hdr
 * ----------------
 * Utility function that returns a pointer to the HEADER given a pointer to the data segment.
 */
void *jmp_to_hdr(void *blk_ptr) {
    return (void *)((char *)blk_ptr - HEADER_SIZE);
}

/* Function: jmp_to_parent_ptr
 * ----------------
 * Utility function that returns a pointer to the location where the location of the previous free list entry is stored.
 */
void *jmp_to_parent_ptr(void *free_hdr_ptr) {
    return (void *)((char *)free_hdr_ptr + HEADER_SIZE);
}

/* Function: jmp_to_child_ptr
 * ----------------
 * Utility function that returns a pointer to the location where the location of the next free list entry is stored.
 */
void *jmp_to_child_ptr(void *free_hdr_ptr) {
    return (void *)((char *)free_hdr_ptr + HEADER_SIZE + HEADER_SIZE);
}

/* Function: write_parent_ptr
 * ----------------
 * Utility function that writes in the pointer to the previous free list entry, given the HEADER pointer.
 */
void write_parent_ptr(void *free_hdr_ptr, void *parent_ptr) {
    void *parent_ptr_loc = jmp_to_parent_ptr(free_hdr_ptr);
    *(HEADER **)(parent_ptr_loc) = parent_ptr;
}

/* Function: write_child_ptr
 * ----------------
 * Utility function that writes in the pointer to the next free list entry, given the HEADER pointer.
 */
void write_child_ptr(void *free_hdr_ptr, void *child_ptr) {
    void *child_ptr_loc = jmp_to_child_ptr(free_hdr_ptr);
    *(HEADER **)(child_ptr_loc) = child_ptr;
}

/* Function: get_parent_ptr
 * ----------------
 * Utility function that retrieves the pointer to the previous free list entry.
 */
void *get_parent_ptr(void *free_hdr_ptr) {
    return *(HEADER **)(jmp_to_parent_ptr(free_hdr_ptr));
}

/* Function: get_child_ptr
 * ----------------
 * Utility function that retrieves the pointer to the next free list entry.
 */
void *get_child_ptr(void *free_hdr_ptr) {
    return *(HEADER **)(jmp_to_child_ptr(free_hdr_ptr));
}

/* Function: add_free_list_entry
 * ----------------
 * Utility function that adds an allocation to the free list and rewires as needed.
 */
void add_free_list_entry(void *free_hdr_ptr) {
    write_parent_ptr(free_hdr_ptr, NULL);
    write_child_ptr(free_hdr_ptr, top_free_list);
    if (top_free_list != NULL) {
        write_parent_ptr(top_free_list, free_hdr_ptr);
    }
    top_free_list = free_hdr_ptr;
}

/* Function: remove_free_list_entry
 * ----------------
 * Utility function that removes an allocation from the free list and rewires as needed.
 */
void remove_free_list_entry(void *free_hdr_ptr) {
    void *parent = get_parent_ptr(free_hdr_ptr);
    void *child = get_child_ptr(free_hdr_ptr);

    if (parent == NULL) {
        top_free_list = child;
    }
    else {
        write_child_ptr(parent, child);
    }

    if (child != NULL) {
        write_parent_ptr(child, parent);
    }
}

/* Function: coalesce_right
 * ----------------
 * Utility function that combines all of the neighboring free blocks on the right into the block pointed to by the pointer.
 * Works for both free and used blocks. The end result always matches the in-use status of the original.
 */
void coalesce_right(void *hdr_ptr) {
    void *master_hdr = hdr_ptr;
    void *slave_hdr = next_hdr(hdr_ptr);

    while (valid_heap_ptr(slave_hdr) && !is_used(slave_hdr)) {
        size_t master_hdr_size = get_alloc_size(master_hdr);
        size_t slave_hdr_size = get_alloc_size(slave_hdr);

        HEADER new_master_hdr = make_hdr(master_hdr_size + slave_hdr_size + HEADER_SIZE, is_used(master_hdr));

        remove_free_list_entry(slave_hdr);

        place_hdr(master_hdr, new_master_hdr);

        slave_hdr = next_hdr(master_hdr);

    }
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
    top_free_list = myheap_start;
    write_parent_ptr(myheap_start, NULL);
    write_child_ptr(myheap_start, NULL);

    return true;
}

/* Function: mymalloc
 * -----------------
 * This function allocates the requested number of bytes and returns a pointer to the allocated memory. If the allocation is
 * placed in a free block large enough that there is space leftover sufficient for an additional allocation, the block is split
 * and a new free block is created with the leftover space.
 */
void *mymalloc(size_t requested_size) {
    size_t rounded_request = roundup(requested_size, ALIGNMENT);

    if (rounded_request < MINIMUM_SIZE) {
        rounded_request = MINIMUM_SIZE;
    }

    void *hdr_ptr = top_free_list;

    while (valid_heap_ptr(hdr_ptr)) {
        size_t available_space = get_alloc_size(hdr_ptr);

        if (available_space >= rounded_request) {
            // Case 1: Too little extra space in the free block for a new header, so expand the allocation.
            if (available_space - rounded_request < MINIMUM_SIZE) {
                rounded_request = available_space;
                HEADER allocation_header = make_hdr(rounded_request, true);
                remove_free_list_entry(hdr_ptr);
                place_hdr(hdr_ptr, allocation_header);
                return jmp_to_blk(hdr_ptr);
            }

            // Case 2: Enough extra space in the free block to merit an additional header.
            HEADER allocation_header = make_hdr(rounded_request, true);
            place_hdr(hdr_ptr, allocation_header);
            void *next_header = next_hdr(hdr_ptr);
            remove_free_list_entry(hdr_ptr);
            // The next four lines create and integrate the leftover free block into the heap segment.
            HEADER leftover_header = make_hdr(available_space - rounded_request - HEADER_SIZE, false);
            add_free_list_entry(next_header);
            place_hdr(next_header, leftover_header);
            coalesce_right(next_header);
            return jmp_to_blk(hdr_ptr);

        }

        // If the current header is not a sufficiently sized free block, jump to the next header.
        hdr_ptr = get_child_ptr(hdr_ptr);

    }
    
    // If we exit the for loop with no free block found for the request, we have failed.
    return NULL;
}

/* Function: myfree
 * -----------------
 * This function deallocates the allocation pointed to by the pointer. It also combines the newly created free
 * block with any free blocks found immediately to its right.
 */
void myfree(void *blk_ptr) {
    if (valid_heap_ptr(blk_ptr)) {
        void *hdr_ptr = jmp_to_hdr(blk_ptr);
        flip_status(hdr_ptr);
        add_free_list_entry(hdr_ptr);
        coalesce_right(hdr_ptr);
    }
}

/* Function: myrealloc
 * -----------------
 * This function deallocates the old object pointed to by orig_loc and returns a pointer to a 
 * new allocation that has the size specified by new_size. The contents of the new allocation are 
 * the same as those of the old allocation, up to the smaller of the new and old sizes. This
 * implementation adds the capability to resize allocations in place whenever possible, which
 * reduces instruction count by eliminating memory copying in many cases.
 */
void *myrealloc(void *orig_loc, size_t new_size) {   
    // Handles special case where the old pointer is null.
    if (!valid_heap_ptr(orig_loc)) {
        return mymalloc(new_size);
    }

    // Handles special case where requested size is zero.
    if (new_size == 0) {
        return NULL;
    }

    void* orig_hdr = jmp_to_hdr(orig_loc);

    // First, we absorb all frees to the right of the block we've been requested to realloc.
    coalesce_right(orig_hdr);

    // We can then decide whether we can do in-place realloc, or if we need to move it.
    size_t coalesced_size = get_alloc_size(orig_hdr);
    size_t rounded_new_size = roundup(new_size, ALIGNMENT);

    // Ensures that no allocation too small to be freed is inadvertently created.
    if (rounded_new_size < MINIMUM_SIZE) {
        rounded_new_size = MINIMUM_SIZE;
    }

    // Case 1: The new alloc fits and there is room for an additional header.
    if (rounded_new_size + MINIMUM_SIZE <= coalesced_size) {
        HEADER new_header = make_hdr(rounded_new_size, true);
        place_hdr(orig_hdr, new_header);
        // The next five lines create and integrate the leftover free block into the heap segment.
        void *additional_header_space = next_hdr(orig_hdr);
        HEADER leftover_header = make_hdr(coalesced_size - rounded_new_size - HEADER_SIZE, false);
        place_hdr(additional_header_space, leftover_header);
        add_free_list_entry(additional_header_space);
        return orig_loc;
    }

    // Case 2: The new alloc fits, but there is not enough room for another block.
    else if (coalesced_size - MINIMUM_SIZE < rounded_new_size && rounded_new_size <= coalesced_size) {
        return orig_loc;
    }

    // Case 3: The new alloc does not fit. Thus, we must move the allocation.
    else if (coalesced_size < rounded_new_size) {
        void *new_location = mymalloc(rounded_new_size);
        memcpy(new_location, orig_loc, get_alloc_size(orig_hdr));
        myfree(orig_loc);
        return new_location;
    }

    return NULL;
}

/* Function: validate_heap
 * ----------------
 * This function verifies that the heap is not corrupted.
 * First check: for each header, the three least significant bits contain only the used/free info.
 * Second check: the total count of free bytes, header bytes, and used bytes sums to the segment size.
 * Third check: Every link in the doubly linked list goes both ways.
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

            if (get_child_ptr(hdr_ptr) != NULL && get_parent_ptr(hdr_ptr) != NULL) {

                if (get_child_ptr(get_parent_ptr(hdr_ptr)) != hdr_ptr || get_parent_ptr(get_child_ptr(hdr_ptr)) != hdr_ptr) {
                    printf("Block #%lu has an issue with its free pointers.", block_number);
                    return false;
                }

            }

            
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
 * Utility function that maps out the status of the entire heap segment.
 */
void dump_heap() {
    printf("\n\n\nThe allocated heap segment starts at address %p, and ends at %p.\n", myheap_start, (char *)myheap_start + myheap_size);
    printf("The location of the latest FREE block header is stored as %p.\n\n", top_free_list);

    void *hdr_ptr = myheap_start;
    size_t block_counter = 0;
    
    while (valid_heap_ptr(hdr_ptr)) {
        HEADER current_header = get_hdr(hdr_ptr);
        size_t alloc_size = (current_header & SIZE_MASK);
        bool alloc_used = (current_header & USED_MASK);
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

/* Function: dump_list
 * ----------------
 * Utility function that maps out the doubly linked list for the free blocks.
 */
void dump_list() {
    printf("The allocated heap segment starts at address %p, and ends at %p.\n", myheap_start, (char *)myheap_start + myheap_size);
    printf("The location of the latest FREE block header is stored as %p.\n\n", top_free_list);

    void *hdr_ptr = myheap_start;
    size_t block_counter = 0;
    
    while (valid_heap_ptr(hdr_ptr)) {
        HEADER current_header = get_hdr(hdr_ptr);
        bool alloc_used = (current_header & USED_MASK);
        if (!alloc_used) {
            printf("This FREE, at %p, has a prev pointer %p and a next pointer %p.\n", hdr_ptr, get_parent_ptr(hdr_ptr), get_child_ptr(hdr_ptr));
        }
        block_counter += 1;
        hdr_ptr = next_hdr(hdr_ptr);
    }
}