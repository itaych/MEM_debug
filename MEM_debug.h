/*
MEM_debug, a heap corruption and memory leak detector.

Copyright (c)2019 Itay Chamiel, itaych@gmail.com

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product or in the course of product development, an acknowledgment
    in the product documentation would be appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

    3. This notice may not be removed or altered from any source distribution.
*/

#ifndef MEM_DEBUG_H_
#define MEM_DEBUG_H_

#include <stddef.h>
#include <stdint.h>

// Comment this line out to completely disable the memory checker.
#define MEM_DEBUG_ENABLE

#ifdef __cplusplus

/* C++ interface */

namespace mem_debug {

#ifdef MEM_DEBUG_ENABLE

// Checks integrity of all allocated memory and displays results. It is best not to use this function directly but use one of the below macros.
void mem_debug_check(const char* file, const int line, const char* user_msg = NULL, const bool this_thread_only = false);

// Performs integrity check and displays amount and size of all memory allocation.
#define MEM_DEBUG_CHECK mem_debug::mem_debug_check(__FILE__, __LINE__);
// Same as MEM_DEBUG_CHECK but allows a custom message to be shown along with results.
#define MEM_DEBUG_CHECK_MSG(msg) mem_debug::mem_debug_check(__FILE__, __LINE__, msg);
// Same as MEM_DEBUG_CHECK_MSG but displays results for memory allocated by the calling thread only.
#define MEM_DEBUG_THREAD_CHECK(msg) mem_debug::mem_debug_check(__FILE__, __LINE__, msg, true);

// Integrity check on a single pointer; this will only work on a pointer that can be unallocated using 'free'. (that is, obtained by a previous
// use of malloc or similar call and not modified). It has also been tested on pointers obtained via 'new' but this is may fail on certain platforms.
void mem_debug_check_ptr(const void* ptr);

// Clear records of allocated memory, to prepare for a leak test.
// is_global defines scope of operation, true for process-wide, false for current thread's allocations only.
// restart_serial_nums also resets all (process/thread) allocations' serial numbers, and restarts assignment from 0.
void mem_debug_clear_leak_list(bool is_global = false, bool restart_serial_nums = false);

// Display all memory buffers allocated since the last clear_leak_list (or program start).
// is_global=true to display all process's allocs, false to display current thread's only.
// returns false if no leaks detected, true if leaks detected.
bool mem_debug_show_leak_list(bool is_global = false);

// Cause mem_debug to abort the program on a specific allocation (defined by serial number), optionally only if equal to a specific size, global or in current thread.
void mem_debug_abort_on_allocation(unsigned int serial_num, unsigned int size = 0, bool is_global = false);

// Returns total amount of bytes currently allocated by program (with or without extra padding allocated by mem_debug).
// Setting get_peak to true will return the respective current peak value.
// Setting is_global to false will return information pertaining to current thread only (this feature requires c++11, 0 will be returned otherwise).
uint64_t mem_debug_total_alloced_bytes(bool include_padding = false, bool get_peak = false, bool is_global = true);

#else
static inline void mem_debug_check(const char* file, const int line, const char* user_msg = NULL, const bool this_thread_only = false) {}
static inline void mem_debug_check_ptr(const void* ptr) {}
static inline void mem_debug_clear_leak_list(bool is_global = false, bool restart_serial_nums = false) {}
static inline bool mem_debug_show_leak_list(bool is_global = false) { return false; }
static inline void mem_debug_abort_on_allocation(unsigned int serial_num, unsigned int size = -1, bool is_global = false) {}
static inline uint64_t mem_debug_total_alloced_bytes(bool include_padding = false, bool get_peak = false, bool is_global = true) { return 0; }
#define MEM_DEBUG_CHECK
#define MEM_DEBUG_CHECK_MSG(msg)
#define MEM_DEBUG_THREAD_CHECK(msg)
#endif

} // namespace

#else // __cplusplus not defined

/* C language interface. Functionality is the same as above but substitute integer constants MD_TRUE and MD_FALSE for true/false boolean values. */

#define MD_TRUE 1
#define MD_FALSE 0

#ifdef MEM_DEBUG_ENABLE
void mem_debug_check(const char* file, const int line, const char* user_msg, const int bool_this_thread_only);
#define MEM_DEBUG_CHECK mem_debug_check(__FILE__, __LINE__, NULL, MD_FALSE);
#define MEM_DEBUG_CHECK_MSG(msg) mem_debug_check(__FILE__, __LINE__, msg, MD_FALSE);
#define MEM_DEBUG_THREAD_CHECK(msg) mem_debug_check(__FILE__, __LINE__, msg, MD_TRUE);
void mem_debug_check_ptr(const void* ptr);
void mem_debug_clear_leak_list(int bool_is_global, int bool_restart_serial_nums);
int mem_debug_show_leak_list(int bool_is_global);
void mem_debug_abort_on_allocation(unsigned int serial_num, unsigned int size, int bool_is_global);
uint64_t mem_debug_total_alloced_bytes(int bool_include_padding, int get_peak, int is_global);
#else
static inline void mem_debug_check(const char* file, const int line, const char* user_msg, const int bool_this_thread_only) {}
static inline void mem_debug_check_ptr(const void* ptr) {}
static inline void mem_debug_clear_leak_list(int bool_is_global, int bool_restart_serial_nums) {}
static inline int mem_debug_show_leak_list(int bool_is_global) { return MD_FALSE; }
static inline void mem_debug_abort_on_allocation(unsigned int serial_num, unsigned int size, int bool_is_global) {}
static inline uint64_t mem_debug_total_alloced_bytes(int bool_include_padding, int get_peak, int is_global) { return 0; }
#define MEM_DEBUG_CHECK
#define MEM_DEBUG_CHECK_MSG(msg)
#define MEM_DEBUG_THREAD_CHECK(msg)
#endif

#endif // __cplusplus

#endif /* MEM_DEBUG_H_ */
