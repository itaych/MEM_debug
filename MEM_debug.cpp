/*
MEM_debug, a heap corruption and memory leak detector.

Copyright (c)2021 Itay Chamiel, itaych@gmail.com

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

// Here are some user modifiable settings.

// Uncomment to enable filling of all allocated memory with a fixed value. This is useful to catch use of uninitialized data. Causes an additional performance hit.
//#define MEM_DEBUG_FILL_ALLOCED_MEMORY
// Uncomment to enable filling of all freed memory with a fixed value. This is useful to catch use of freed data. Causes an additional performance hit.
//#define MEM_DEBUG_FILL_FREED_MEMORY
// Size of padding before and after each allocation, for catching out of bounds writes. They can be any value from 0 up. Performance and memory
// use are affected because these pads are filled when allocating and tested when freeing.
// Note that these values are guaranteed minimums but the actual padding sizes may be slightly higher.
#define PREFIX_SIZE 32
#define SUFFIX_SIZE 32
// All padding is filled with this byte.
#define PAD_CHAR 0xda
// If MEM_DEBUG_FILL_FREED_MEMORY is defined, fill freed memory with this value.
#define PAD_FREEMEM_CHAR 0xcd
// Fail on any single allocation request larger than this size. This catches unintentional huge allocations but increase this value if desired.
#define MAX_ALLOC 0x18000000 // 384 MB
// File descriptor to which error messages shall be output. Recommended values are STDOUT_FILENO or STDERR_FILENO.
#define ERROR_OUT_FD STDOUT_FILENO
// By default, diagnostic functions output messages using printf, but if you use some framework that supports log levels you may
// employ it by changing these defines.
#define MD_LOG_INFO printf
#define MD_LOG_WARNING printf
#define MD_LOG_ERROR printf

// End of user defines.

#include "MEM_debug.h"

#ifdef MEM_DEBUG_ENABLE

#pragma message "Memory debugger ENABLED"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <map>
#include <new>

#define MEM_DEBUG_NAME "MEM_debug "
#define MEM_DEBUG_VERSION "1.0.16"

// Optimize an 'if' for the most likely case
#ifdef __GNUC__
#define LIKELY(x)		__builtin_expect(!!(x), 1)
#define UNLIKELY(x)		__builtin_expect(!!(x), 0)
#else
#define LIKELY(x) x
#define UNLIKELY(x) x
#endif

// This is called when an error is found and we want to kill the program.
#define __THROW_ERROR__ raise(SIGSEGV) /* Crash the program. */

// rounds up to any power of 2
#define ROUND_UP(value, round_to) (((value) + (round_to - 1)) & ~(round_to - 1))

// these are aliases to the original glibc malloc/free functions.
extern "C" void *__libc_malloc(size_t size);
extern "C" void __libc_free(void *__ptr);
// extern "C" void *__libc_memalign (size_t alignment, size_t size);

// magic numbers to ensure an allocation is real
#define MAGIC_NUM 0x1ee76502
#define MAGIC_NUM_DELETED 0xdeadbeef

// A header added to each allocated memory block
struct mem_hdr {
	uint32_t magic_num;
	mem_hdr* prev;
	mem_hdr* next;
	uint32_t prefix_addr_offset;
	uint32_t suffix_offset;
	uint32_t total_alloc_size;
	uint32_t requested_size;
	// statistics
	uint32_t serial_num;
	uint32_t serial_num_per_thread;
	bool leak_detect_flag;
	long int allocator_thread;
	timeval timestamp; // time stamp of allocation
	uint32_t checksum; // ensures integrity of this struct

	uint32_t calc_checksum() { return (unsigned long)prev + (unsigned long)next
			+ prefix_addr_offset + suffix_offset + total_alloc_size + requested_size
			+ serial_num + serial_num_per_thread + allocator_thread
			+ timestamp.tv_sec + timestamp.tv_usec; }
};

// Headers are connected as a doubly-linked list. This is the head node.
static mem_hdr mem_hdr_base = {0, NULL, NULL, 0, 0, 0, 0};
// bookkeeping
static int num_global_allocs = 0; // amount of blocks currently allocated.
static uint64_t global_num_times_malloc_called = 0; // total amount of times 'malloc' was called
static __thread uint64_t thread_num_times_malloc_called = 0; // total amount of times 'malloc' was called by this thread
static uint64_t global_num_times_free_called = 0; // total amount of times 'free' was called
static __thread uint64_t thread_num_times_free_called = 0; // total amount of times 'free' was called by this thread

static uint64_t global_bytes_alloced = 0; // total memory allocated (by user, not including padding by mem_debug)
static uint64_t global_bytes_alloced_w_padding = 0; // total memory allocated (including paddings)
static uint64_t global_bytes_alloced_max = 0; // peak total memory allocated (not including padding)
static uint64_t global_bytes_alloced_w_padding_max = 0; // peak total memory allocated (including padding)
static __thread uint64_t thread_bytes_alloced_max = 0; // peak thread memory allocated (not including padding)
static __thread uint64_t thread_bytes_alloced_w_padding_max = 0; // peak thread memory allocated (including padding)
static uint64_t global_bytes_alloced_limit = 0; // memory usage limit, 0 (unlimited) by default

static size_t max_align = 0; // highest alignment request seen.
static uint32_t alloc_serial_num = 0; // serial number of next allocation (process-wide)
static __thread uint32_t alloc_thread_serial_num = 0; // serial number of next allocation (per thread)

// allow aborting on a specific memory allocation number
#define INVALID_SERIAL ((uint32_t)-1)
static uint32_t abort_on_global_serial_num = INVALID_SERIAL;
static unsigned int abort_on_size_global = 0;
static __thread uint32_t abort_on_thread_serial_num = INVALID_SERIAL;
static __thread unsigned int abort_on_size_thread = 0;

// Thread specific statistics must be dealt with carefully because a memory block may be freed from a different thread from which it was allocated, and cannot be thread_local
// because the allocating thread may have been destroyed. The solution is to store thread specific data in a map.
struct ThreadSpecificInfo {
	int num_thread_allocs; // amount of blocks currently allocated by this thread.
	uint64_t thread_bytes_alloced; // thread memory allocated (by user, not including padding by mem_debug) by this thread,
	uint64_t thread_bytes_alloced_w_padding; // thread memory allocated (including paddings) by this thread.
	ThreadSpecificInfo() : num_thread_allocs(0), thread_bytes_alloced(0), thread_bytes_alloced_w_padding(0) {}
};
// For this map define an allocator that allocates memory directly, bypassing MEM_debug.
template<typename _Tp> class libc_allocator : public std::allocator<_Tp> {
public:
	template<typename _Tp1> struct rebind { typedef libc_allocator<_Tp1> other; };
	libc_allocator() throw() {}
	template <typename _Tp1> libc_allocator (const libc_allocator<_Tp1>&) throw() {}
	_Tp* allocate(size_t __n, const void* unused = 0) {
		return static_cast<_Tp*>(__libc_malloc(__n * sizeof(_Tp)));
	}
	void deallocate(_Tp* __p, size_t unused) {
		__libc_free(__p);
	}
};
typedef std::map<long int, ThreadSpecificInfo, std::less<int>, libc_allocator<std::pair<const long int, ThreadSpecificInfo> > > ThreadSpecificInfoMap;
// This map cannot be a static object, as it may not be initialized at first memory allocation, so only allocate space for it.
uint64_t thread_specific_info_map_space[sizeof(ThreadSpecificInfoMap)/sizeof(uint64_t)+1]; // uint64_t to force alignment, +1 because division my cause a too small size
// Create the map during the first memory allocation and set this pointer.
static ThreadSpecificInfoMap *thread_specific_info = nullptr;
// ensure that map is created only once (for a clean shutdown sequence)
bool thread_specific_info_created = false;

// compare memory to constant byte. returns true iff all bytes in memory are equal to val.
// by stackoverflow user mihaif. http://stackoverflow.com/a/28563801/3779334
static inline bool memvcmp(const void *memory, const unsigned char val, const unsigned int size) {
	if (!size) {
		return true;
	}
	const unsigned char *mm = (const unsigned char*)memory;
	return (*mm == val) && (memcmp(mm, mm + 1, size - 1) == 0);
}

// a version of 'write' that ignores the return value (we don't expect errors when writing to stderr).
static inline void void_write (int __fd, __const void *__buf, size_t __n) {
	size_t ret = write(__fd, __buf, __n);
	((void)ret);
}

// some 'safe' print functions, so we don't call printf within alloc/free
static void safe_print_string(const char* str, const int fd = ERROR_OUT_FD) {
	const char* str_p = str;
	while (*str_p) {
		str_p++;
	}
	void_write(fd, str, str_p-str);
}

static void safe_print_string_escaped(const char* str, const int fd = ERROR_OUT_FD) {
	while (*str) {
		if (*str == '\t') safe_print_string("\\t");
		else if (*str == '\n') safe_print_string("\\n");
		else if (*str == '\r') safe_print_string("\\r");
		else void_write(fd, str, 1);
		str++;
	}
}

static void safe_print_hex(uint64_t val, const int fd = ERROR_OUT_FD) {
	char digits[19]; // 0x + 16 digits + null terminator
	char* current = digits + sizeof(digits);
	*--current = '\0';
	do {
		char hex_digit = val & 0xf;
		if (hex_digit < 0xa) {
			hex_digit += '0';
		}
		else {
			hex_digit += 'a' - 0xa;
		}
		*--current = hex_digit;
		val >>= 4;
	} while (val != 0);
	*--current = 'x';
	*--current = '0';
	safe_print_string(current);
}

static void safe_print_dec(uint64_t val, const int fd = ERROR_OUT_FD) {
	char digits[21]; // 20 digits + null terminator
	char* current = digits + sizeof(digits);
	*--current = '\0';
	do {
		*--current = '0' + (val % 10);
		val /= 10;
	} while (val != 0);
	safe_print_string(current);
}

static void safe_print_with_hex_val(const char* str1, uint64_t val, const char* str2, const int fd = ERROR_OUT_FD) {
	safe_print_string(str1, fd);
	safe_print_hex(val, fd);
	safe_print_string(str2, fd);
}

static void safe_print_with_dec_val(const char* str1, uint64_t val, const char* str2, const int fd = ERROR_OUT_FD) {
	safe_print_string(str1, fd);
	safe_print_dec(val, fd);
	safe_print_string(str2, fd);
}

// get thread ID (no more than once per thread)
static long int get_thread_id() {
	static __thread long int thread_id = syscall(SYS_gettid);
	return thread_id;
}

// Critical section mutex.
static pthread_mutex_t alloc_mutex;
static bool is_alloc_mutex_inited = false;
static __thread bool is_mutex_owned = false; // catch malloc double lock within the same thread
static inline void mutex_lock() {
	if (UNLIKELY(!is_alloc_mutex_inited)) {
		pthread_mutex_init(&alloc_mutex, NULL);
		is_alloc_mutex_inited = true;
	}
	if (UNLIKELY(is_mutex_owned)) {
		safe_print_with_dec_val(MEM_DEBUG_NAME "Mutex double lock from thread ", (uint64_t)get_thread_id(), "!\n");
		pthread_mutex_unlock(&alloc_mutex);
		is_mutex_owned = false;
		__THROW_ERROR__;
	}
	pthread_mutex_lock(&alloc_mutex);
	is_mutex_owned = true;
}
static inline void mutex_unlock() {
	if (UNLIKELY(!is_mutex_owned)) {
		safe_print_string(MEM_DEBUG_NAME "Mutex invalid unlock!\n");
		__THROW_ERROR__;
	}
	pthread_mutex_unlock(&alloc_mutex);
	is_mutex_owned = false;
}

// Dummy object that announces memory checker at startup and runs final check at shutdown.
struct MemDebugInfo {
	MemDebugInfo() { safe_print_with_dec_val("** (", getpid(), ") " MEM_DEBUG_NAME MEM_DEBUG_VERSION " is active.\n"); }
	~MemDebugInfo() {
		const int MAX_EXIT_MSG_STR=128;
		char msg[MAX_EXIT_MSG_STR];
		snprintf(msg, MAX_EXIT_MSG_STR, "- At shutdown (peak memory use was %llu bytes, padded %llu. %llu mallocs, %llu frees)",
				(unsigned long long)global_bytes_alloced_max, (unsigned long long)global_bytes_alloced_w_padding_max,
				(unsigned long long)global_num_times_malloc_called, (unsigned long long)global_num_times_free_called);
		mem_debug::mem_debug_check(__FILE__, __LINE__, msg);
		// Since we're shutting down, use this opportunity to delete thread_specific_info map
		mutex_lock();
		if (thread_specific_info) {
			thread_specific_info->~ThreadSpecificInfoMap();
			thread_specific_info = nullptr;
		}
		mutex_unlock();
	}
};
static MemDebugInfo memdebuginfo;

// Get thread and timestamp from memory header and create human readable output.
static __thread char hdr_info_output[0x100];
static char* hdr_info(const struct mem_hdr* hdr, bool show_extra_info = false) {
	struct tm currtime;

	// convert mem TS to string
	localtime_r(&hdr->timestamp.tv_sec, &currtime); // local time
	char ts_str[32];
	strftime(ts_str, sizeof(ts_str), "%b %e %X.", &currtime);

	// generate output
	snprintf(hdr_info_output, sizeof(hdr_info_output), "Allocated at %s%03d by thread %d size %u",
			ts_str, (int)(hdr->timestamp.tv_usec/1000), (int)hdr->allocator_thread, hdr->requested_size);

	if (show_extra_info) { // add info on current time and thread.
		// convert current time to string
		timeval now_ts;
		gettimeofday(&now_ts, NULL);
		localtime_r(&now_ts.tv_sec, &currtime); // local time
		strftime(ts_str, sizeof(ts_str), "%b %e %X.", &currtime);
		// add to output
		snprintf(hdr_info_output+strlen(hdr_info_output), sizeof(hdr_info_output)-strlen(hdr_info_output),
				" (Now: %s%03d thread %d)",
				ts_str, (int)(now_ts.tv_usec/1000), (int)get_thread_id());
	}
	return hdr_info_output;
}

// allocate aligned memory. Other allocators call this function.
static int mem_debug_posix_memalign(void **memptr, size_t alignment, size_t size) {
#define MALLOC_PFX MEM_DEBUG_NAME "malloc: "
	long int thread_id = get_thread_id();

	if (UNLIKELY(size == 0)) { // alloc(0) returns null
		*memptr = NULL;
		return 0;
	}
	if (alignment & (alignment-1)) { // alignment not power of 2?
		safe_print_with_dec_val(MALLOC_PFX "bad align ", alignment, "\n");
		__THROW_ERROR__;
	}
	const size_t MIN_ALIGNMENT = sizeof(void*) * 2; // minimum alignment, 8 bytes for 32-bit systems, 16 bytes for 64-bit.
	if (alignment < MIN_ALIGNMENT) {
		alignment = MIN_ALIGNMENT;
	}
	if (alignment > max_align) { // remember highest alignment request we've seen.
		max_align = alignment;
	}

	if (size > MAX_ALLOC) { // catch invalid allocation sizes
		safe_print_string(MALLOC_PFX "bad alloc size ");
		safe_print_dec(size);
		safe_print_string(", max allowed ");
		safe_print_dec(MAX_ALLOC);
		safe_print_string("\n");
		*memptr = NULL;
		//__THROW_ERROR__;
		return -1;
	}

	// We allocate buffers that look like this:
	// [ mem_hdr struct | PREFIX_SIZE_ACTUAL bytes | alignment padding (if needed) | allocated buffer for user | SUFFIX_SIZE bytes ]
	// Immediately below the user buffer we set a pointer to the prefix header. Since alignment padding and PREFIX_SIZE might both be zero,
	// leaving no room for this pointer, we add sizeof(void*) to PREFIX_SIZE.
	// Any space reserved for alignment padding but not actually used for padding, is added to the suffix.
#define PREFIX_SIZE_ACTUAL (PREFIX_SIZE + sizeof(void*))
	uint32_t total_alloc_size = sizeof(mem_hdr)+PREFIX_SIZE_ACTUAL+alignment+size+SUFFIX_SIZE;
	// allocate using libc malloc
	uint8_t* ptr = (uint8_t*)__libc_malloc(total_alloc_size);
	if (!ptr) { // allocation failure?
		safe_print_string(MALLOC_PFX "__libc_malloc fail! Requested size ");
		safe_print_dec(size);
		safe_print_string(", total requested ");
		safe_print_dec(total_alloc_size);
		safe_print_string(", already alloced ");
		safe_print_dec(global_bytes_alloced_w_padding);
		safe_print_string("\n");
		*memptr = NULL;
		//__THROW_ERROR__;
		return -1;
	}
#ifdef MEM_DEBUG_FILL_ALLOCED_MEMORY
	memset(ptr, PAD_CHAR, total_alloc_size); // fill entire block with pad char
#endif

	uint8_t* prefix = (uint8_t*)ptr;
	// push ptr to end of prefix
	ptr = prefix + sizeof(mem_hdr) + PREFIX_SIZE_ACTUAL;
	// round ptr up to requested alignment. This will be the returned allocated buffer.
	uint64_t ptr_num = (uint64_t)ptr;
	uint64_t ptr_num_rounded = ROUND_UP(ptr_num, alignment);
	ptr = (uint8_t*)ptr_num_rounded;
	// create a pointer, just below the allocated buffer, pointing to start of prefix.
	void** ptr_write_prefix_addr = ((void**)ptr) - 1;
	*ptr_write_prefix_addr = prefix;

	// create a mem_hdr struct at start of prefix.
	mem_hdr* m = (mem_hdr*)prefix;
	m->magic_num = MAGIC_NUM;
	m->prefix_addr_offset = (uint8_t*)ptr_write_prefix_addr - prefix; // offset to pointer at end of prefix
	m->suffix_offset = (ptr+size) - prefix; // offset to start of suffix (end of user buffer)
	m->total_alloc_size = total_alloc_size; // offset to end of suffix (end of entire allocated block)
	m->requested_size = size; // remember user's requested size
	m->serial_num = alloc_serial_num++;
	m->serial_num_per_thread = alloc_thread_serial_num++;
	m->leak_detect_flag = true;
	m->allocator_thread = thread_id;
	gettimeofday(&m->timestamp, NULL);

	// abort if we've reached a user requested serial number.
	if ((abort_on_global_serial_num != INVALID_SERIAL && m->serial_num == abort_on_global_serial_num && (abort_on_size_global == 0 || abort_on_size_global == size)) ||
		(abort_on_thread_serial_num != INVALID_SERIAL && m->serial_num_per_thread == abort_on_thread_serial_num && (abort_on_size_thread == 0 || abort_on_size_thread == size))) {
		safe_print_with_dec_val(MALLOC_PFX "reached requested allocation number, size ", size, ", aborting\n");
		__THROW_ERROR__;
	}

#ifndef MEM_DEBUG_FILL_ALLOCED_MEMORY
	// fill prefix from end of mem_hdr struct until prefix pointer.
	memset(prefix+sizeof(mem_hdr), PAD_CHAR, m->prefix_addr_offset-sizeof(mem_hdr));
	memset(prefix+m->suffix_offset, PAD_CHAR, m->total_alloc_size-m->suffix_offset);
#endif

	// manipulating linked list in a critical section.
	mutex_lock();

	// add new node between root node and first node.
	mem_hdr* first_node = mem_hdr_base.next;
	if (first_node) {
		first_node->prev = m;
		first_node->checksum = first_node->calc_checksum();
	}
	m->next = first_node;
	mem_hdr_base.next = m;
	m->prev = &mem_hdr_base;

	global_bytes_alloced += size;
	global_bytes_alloced_w_padding += total_alloc_size;
	if (global_bytes_alloced > global_bytes_alloced_max) {
		global_bytes_alloced_max = global_bytes_alloced;
		global_bytes_alloced_w_padding_max = global_bytes_alloced_w_padding;
	}

	// create thread statistics map
	if (!thread_specific_info_created) {
		thread_specific_info = new((void*)thread_specific_info_map_space) ThreadSpecificInfoMap(); // "placement new" creates an object in preallocated memory
		thread_specific_info_created = true;
	}

	// update thread specific statistics
	if (thread_specific_info) { // this pointer is reset in ~MemDebugInfo() so we must check it here
		ThreadSpecificInfo &th = (*thread_specific_info)[thread_id];
		th.num_thread_allocs++;
		th.thread_bytes_alloced += size;
		th.thread_bytes_alloced_w_padding += total_alloc_size;
		if (th.thread_bytes_alloced > thread_bytes_alloced_max) {
			thread_bytes_alloced_max = th.thread_bytes_alloced;
			thread_bytes_alloced_w_padding_max = th.thread_bytes_alloced_w_padding;
		}
	}

	m->checksum = m->calc_checksum();
	global_num_times_malloc_called++;
	thread_num_times_malloc_called++;
	num_global_allocs++;
	mutex_unlock();

	// check that we haven't allocated more than user defined memory limit
	if (global_bytes_alloced_limit > 0 && global_bytes_alloced > global_bytes_alloced_limit) {
		safe_print_with_dec_val(MALLOC_PFX "current alloc is ", size, " bytes, ");
		safe_print_with_dec_val("total is ", global_bytes_alloced, ", ");
		safe_print_with_dec_val("which is beyond limit of ", global_bytes_alloced_limit, ", aborting\n");
		global_bytes_alloced_limit = 0; // handling the abort may require more allocations, prevent them from failing.
		__THROW_ERROR__;
	}

	// return allocated, aligned buffer to user.
	*memptr = ptr;
	return 0;
}

// free memory
void free(void *__ptr) throw() {
#define FREE_PFX MEM_DEBUG_NAME "free: "
	if (!__ptr) {
		return; // free(NULL) does nothing.
	}
	bool err = false;

	// Find pointer to prefix just below the user buffer.
	void** prefix_addr = ((void**)__ptr) - 1;
	uint8_t* prefix = (uint8_t*)*prefix_addr;

	// make sure prefix address is valid. It must be no further from the user's buffer than the prefix size plus the highest alignment requested.
	int64_t difftest = (uint8_t*)__ptr - prefix;
	if (difftest < (int64_t)(PREFIX_SIZE_ACTUAL + sizeof(mem_hdr)) || difftest > (int64_t)(PREFIX_SIZE_ACTUAL + sizeof(mem_hdr) + max_align)) {
		safe_print_with_hex_val(FREE_PFX "error! prefix broken (wrong pointer freed or write before allocation) - ", (uint64_t)__ptr, "\n");
		__THROW_ERROR__;
	}

	// Assume we have a mem_hdr struct at the start of the prefix.
	mem_hdr* m = (mem_hdr*)prefix;

	mutex_lock();

	// All valid allocations must have a magic number here.
	if (m->magic_num != MAGIC_NUM) {
		if (m->magic_num == MAGIC_NUM_DELETED) {
			safe_print_with_hex_val(FREE_PFX "error! double free? ", (uint64_t)__ptr, "\n");
		}
		else {
			safe_print_with_hex_val(FREE_PFX "error! invalid free? ", (uint64_t)__ptr, "\n");
		}
		err = true;
	}
	// validate checksum
	else if (m->checksum != m->calc_checksum()) {
		safe_print_with_hex_val(FREE_PFX "error! corrupted header before ", (uint64_t)__ptr, "\n");
		err = true;
	}
	// make sure prefix pointer in header is correct
	else if (prefix + m->prefix_addr_offset != (uint8_t*)prefix_addr) {
		safe_print_with_hex_val(FREE_PFX "error! corrupted header (prefix ptr bad) before ", (uint64_t)__ptr, "\n");
		err = true;
	}

	if (err) {
		mutex_unlock();
		__THROW_ERROR__;
	}
	else {
		// remove this node from linked list
		m->magic_num = MAGIC_NUM_DELETED;

		mem_hdr* prev_node = m->prev;
		mem_hdr* next_node = m->next;

		prev_node->next = next_node;
		prev_node->checksum = prev_node->calc_checksum();
		if (next_node) {
			next_node->prev = prev_node;
			next_node->checksum = next_node->calc_checksum();
		}
		global_bytes_alloced -= m->requested_size;
		global_bytes_alloced_w_padding -= m->total_alloc_size;

		// update thread specific statistics
		if (thread_specific_info) { // this pointer is set in mem_debug_posix_memalign but reset in ~MemDebugInfo() so we must check it here
			ThreadSpecificInfo &th = (*thread_specific_info)[m->allocator_thread];
			th.num_thread_allocs--;
			th.thread_bytes_alloced -= m->requested_size;
			th.thread_bytes_alloced_w_padding -= m->total_alloc_size;
			if (th.num_thread_allocs <= 0) {
				if (th.thread_bytes_alloced != 0) {
					safe_print_with_dec_val(FREE_PFX "Internal inconsistency for thread ", (uint64_t)m->allocator_thread, ", ");
					safe_print_with_dec_val("there are ", th.thread_bytes_alloced, " bytes allocated when should be 0!\n");
					mutex_unlock();
					__THROW_ERROR__;
				}
				thread_specific_info->erase(m->allocator_thread); // delete info for this thread, since all blocks have been freed.
			}
		}

		global_num_times_free_called++;
		thread_num_times_free_called++;
		num_global_allocs--;
	}

	mutex_unlock();

	// make sure prefix and suffix padding bytes are intact. This is done outside critical section so as not to slow down other threads.
	if (!memvcmp(prefix+sizeof(mem_hdr), PAD_CHAR, m->prefix_addr_offset-sizeof(mem_hdr))) {
		safe_print_with_hex_val(FREE_PFX "error! write before memory - ", (uint64_t)__ptr, "\n");
		__THROW_ERROR__;
	}
	if (!memvcmp(prefix+m->suffix_offset, PAD_CHAR, m->total_alloc_size-m->suffix_offset)) {
		safe_print_with_hex_val(FREE_PFX "error! write after memory - ", (uint64_t)__ptr, "\n");
		__THROW_ERROR__;
	}

#ifdef MEM_DEBUG_FILL_FREED_MEMORY
	// fill memory with garbage so any attempt to use data will fail. Skip magic number.
	memset((uint8_t*)m + sizeof(uint32_t), PAD_FREEMEM_CHAR, m->total_alloc_size - sizeof(uint32_t));
#endif

	// finally free the memory buffer.
	__libc_free(prefix);
}

// Overriding implementations of posix_memalign, memalign, aligned_alloc, valloc, malloc, calloc, realloc - fairly simple, making use of functions defined above.
// (only memalign seemed to require the extern "C", but added it for all of them just in case.)
// Thanks to stackoverflow user Andreas Grapentin for the idea; see his explanation at:
// http://stackoverflow.com/questions/17803456/an-alternative-for-the-deprecated-malloc-hook-functionality-of-glibc

extern "C" int posix_memalign(void **memptr, size_t alignment, size_t size) throw() {
	// We could have directly implemented memory allocation here, but something in the way posix_memalign is declared breaks stack traces
	// in some scenarios. So we avoid it as much as possible (unless the application calls posix_memalign directly).
	return mem_debug_posix_memalign(memptr, alignment, size);
}

extern "C" void *memalign(size_t boundary, size_t size) throw() {
	void* memptr;
	if (mem_debug_posix_memalign(&memptr, boundary, size)) {
		return NULL;
	}
	return memptr;
}

extern "C" void *aligned_alloc(size_t __alignment, size_t __size) throw() {
	return memalign(__alignment, __size);
}

extern "C" void *valloc(size_t size) throw() {
	return memalign(sysconf(_SC_PAGESIZE),size);
}

extern "C" void *malloc(size_t __size) throw() {
	return memalign(0x10, __size);
}

extern "C" void *calloc(size_t __nmemb, size_t __size) throw() {
	size_t sz = __nmemb * __size;
	uint8_t* ret = (uint8_t*)malloc(sz);
	if (ret) {
		memset(ret, 0, sz);
	}
	return ret;
}

extern "C" void *realloc(void *__ptr, size_t __size) throw() {
	if (__ptr == NULL) {
		return malloc(__size); // realloc(NULL, size) is like malloc(size)
	}
	if (__size == 0) {
		free(__ptr); // realloc(ptr, 0) is like free
		return NULL;
	}
	uint8_t* new_ptr = (uint8_t*)malloc(__size); // allocate new buffer
	if (!new_ptr) {
		return NULL;
	}

	// discover size of original buffer - get prefix pointer, as in free()
	void** prefix_addr = ((void**)__ptr) - 1;
	uint8_t* prefix = (uint8_t*)*prefix_addr;
	mem_hdr* m = (mem_hdr*)prefix;

	if (m->magic_num != MAGIC_NUM) {
		safe_print_with_hex_val(MEM_DEBUG_NAME "realloc: error! bad ptr given - ", (uint64_t)__ptr, "\n");
		__THROW_ERROR__;
	}

	// copy minimum of new and previous buffer sizes
	size_t sz_copy = (__size < m->requested_size? __size : m->requested_size);

	// copy buffer contents and free old buffer
	memcpy(new_ptr, __ptr, sz_copy);
	free(__ptr);
	return new_ptr;
}

/* User API */

namespace mem_debug {

// Scan all allocations and test for out of bounds writes and other errors.
void mem_debug_check(const char* file, const int line, const char* user_msg, const bool this_thread_only) {
#define MEM_DEBUG_CHK_PFX "%s:%d%s: error! "
	const char* user_msg_prefix;
	if (user_msg) {
		user_msg_prefix = " ";
	}
	else {
		user_msg = "";
		user_msg_prefix = "";
	}

	long int thread_id = -1;
	int num_allocs_thread = 0;
	uint64_t total_bytes_alloced_thread = 0;

	if (this_thread_only) {
		thread_id = get_thread_id();
	}

	mutex_lock();

	mem_hdr* m = mem_hdr_base.next;
	mem_hdr* prev_m = &mem_hdr_base;
	int num_allocs=0;

	while (m) {
		if (m->magic_num == MAGIC_NUM_DELETED) {
			mutex_unlock();
			MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "bad magic (marked as deleted) - %p\n", file, line, user_msg, m);
			__THROW_ERROR__;
		}
		if (m->magic_num != MAGIC_NUM) {
			mutex_unlock();
			MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "bad magic - %p\n", file, line, user_msg, m);
			__THROW_ERROR__;
		}
		if (m->checksum != m->calc_checksum()) {
			mutex_unlock();
			MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "bad checksum - %p\n", file, line, user_msg, m);
			__THROW_ERROR__;
		}
		if (m->prev != prev_m) {
			mutex_unlock();
			MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "broken linked list - %p points back to %p but expected %p after %d nodes\n", file, line, user_msg, m, m->prev, prev_m, num_allocs);
			__THROW_ERROR__;
		}
		uint8_t* p_addr_offset = (uint8_t*)m + m->prefix_addr_offset;
		uint8_t* orig_alloc = p_addr_offset + sizeof(void**);
		if (*(mem_hdr**)p_addr_offset != m) {
			mutex_unlock();
			MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "bad pointer to header (possible write before allocation) - %p (header %p) %s\n", file, line, user_msg, orig_alloc, m, hdr_info(m));
			__THROW_ERROR__;
		}

		// test padding for overwrites, but skip if we're only checking our own thread's allocations and this one was by a different thread
		if (!this_thread_only || m->allocator_thread == thread_id) {
			uint8_t* prefix = (uint8_t*)m;
			if (!memvcmp(prefix+sizeof(mem_hdr), PAD_CHAR, m->prefix_addr_offset-sizeof(mem_hdr))) {
				mutex_unlock();
				MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "write before allocation - %p (header %p) %s\n", file, line, user_msg, orig_alloc, m, hdr_info(m));
				__THROW_ERROR__;
			}
			if (!memvcmp(prefix+m->suffix_offset, PAD_CHAR, m->total_alloc_size-m->suffix_offset)) {
				mutex_unlock();
				MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "write after allocation - %p (header %p) %s\n", file, line, user_msg, orig_alloc, m, hdr_info(m));
				__THROW_ERROR__;
			}

			if (this_thread_only) {
				num_allocs_thread++;
				total_bytes_alloced_thread += m->requested_size;
			}
		}

		num_allocs++;
		prev_m = m;
		m = m->next;
	}

	const int expected_num_allocs = num_global_allocs; // read global number of allocs in critical section
	mutex_unlock();

	if (num_allocs != expected_num_allocs) {
		MD_LOG_ERROR(MEM_DEBUG_CHK_PFX "wrong num allocs (at %p, num=%d expected=%d)\n", file, line, user_msg, prev_m, num_allocs, expected_num_allocs);
		__THROW_ERROR__;
	}

	if (this_thread_only) {
		MD_LOG_WARNING("%s:%d%s%s: Mem check OK, THREAD %d allocs, %llu bytes\n",
				file, line, user_msg_prefix, user_msg,
				num_allocs_thread, (unsigned long long)total_bytes_alloced_thread);
	}
	else {
		MD_LOG_WARNING("%s:%d%s%s: Mem check OK, %d allocs, %llu bytes (padded %llu)\n",
				file, line, user_msg_prefix, user_msg,
				num_allocs, (unsigned long long)global_bytes_alloced, (unsigned long long)global_bytes_alloced_w_padding);
	}
}

// check validity of a single pointer (this code is very similar to the checks performed in 'free')
void check_ptr(const void* __ptr) {
#define MEM_DEBUG_CHK_PTR_PFX MEM_DEBUG_NAME "%p: error: "
	bool err = false;

	// Find pointer to prefix just below the user buffer.
	const void** prefix_addr = ((const void**)__ptr) - 1;
	const uint8_t* prefix = (const uint8_t*)*prefix_addr;

	// make sure prefix address is valid. It must be no further from the user's buffer than the prefix size plus the highest alignment requested.
	const int64_t difftest = (const uint8_t*)__ptr - prefix;
	if (difftest < (int64_t)(PREFIX_SIZE_ACTUAL + sizeof(mem_hdr)) || difftest > (int64_t)(PREFIX_SIZE_ACTUAL + sizeof(mem_hdr) + max_align)) {
		MD_LOG_ERROR(MEM_DEBUG_CHK_PTR_PFX "prefix broken (invalid pointer or write before allocation)\n", __ptr);
		__THROW_ERROR__;
	}

	// Assume we have a mem_hdr struct at the start of the prefix.
	mem_hdr* m = (mem_hdr*)prefix;

	// All valid allocations must have a magic number here.
	if (m->magic_num != MAGIC_NUM) {
		if (m->magic_num == MAGIC_NUM_DELETED) {
			MD_LOG_ERROR(MEM_DEBUG_CHK_PTR_PFX "memory is freed\n", __ptr);
		}
		else {
			MD_LOG_ERROR(MEM_DEBUG_CHK_PTR_PFX "bad magic\n", __ptr);
		}
		err = true;
	}

	// make sure prefix pointer in header is correct
	else if (prefix + m->prefix_addr_offset != (uint8_t*)prefix_addr) {
		MD_LOG_ERROR(MEM_DEBUG_CHK_PTR_PFX "corrupted header (prefix ptr bad)\n", __ptr);
		err = true;
	}

	if (err) {
		__THROW_ERROR__;
	}

	// make sure prefix and suffix padding bytes are intact.
	if (!memvcmp(prefix+sizeof(mem_hdr), PAD_CHAR, m->prefix_addr_offset-sizeof(mem_hdr))) {
		MD_LOG_ERROR(MEM_DEBUG_CHK_PTR_PFX "write before memory\n", __ptr);
		__THROW_ERROR__;
	}
	if (!memvcmp(prefix+m->suffix_offset, PAD_CHAR, m->total_alloc_size-m->suffix_offset)) {
		MD_LOG_ERROR(MEM_DEBUG_CHK_PTR_PFX "write after memory\n", __ptr);
		__THROW_ERROR__;
	}
}

// Before performing a memory leak check, clear 'leak' flag from all allocations.
// is_global defines whether we clear all or only allocations performed by this thread.
// restart_serial_nums also resets all allocations' serial numbers, and restarts assignment from 0.
void clear_leak_list(bool is_global, bool restart_serial_nums) {
	MD_LOG_INFO(MEM_DEBUG_NAME "Clearing leak table%s.\n", is_global? "":" (this thread only)");

	mutex_lock();
	mem_hdr* m = mem_hdr_base.next;

	while (m) {
		if (is_global || m->allocator_thread == get_thread_id()) {
			m->leak_detect_flag = false; // note that leak_detect_flag is not counted in checksum
			if (restart_serial_nums) {
				if (is_global) {
					m->serial_num = INVALID_SERIAL;
				}
				else {
					m->serial_num_per_thread = INVALID_SERIAL;
				}
				m->checksum = m->calc_checksum();
			}
		}
		m = m->next;
	}
	if (restart_serial_nums) {
		if (is_global) {
			alloc_serial_num = 0;
		}
		else {
			alloc_thread_serial_num = 0;
		}
	}
	mutex_unlock();
}

// Display a list of all memory allocated but not freed since last mem_debug::clear_leak_list (or program start).
// is_global defines whether all allocations are shown, or only those performed by the current thread.
// returns false if no leaks detected, true if leaks detected.
bool show_leak_list(bool is_global) {
#define CONTENT_DUMP_MAX_SIZE 64
#define MAX_OUT_STR 1024
	char out_str[MAX_OUT_STR];

	mutex_lock();
	mem_hdr* m = mem_hdr_base.next;
	bool leaks_detected = false;
	while (m) {
		if ((is_global || m->allocator_thread == get_thread_id()) && m->leak_detect_flag) {
			leaks_detected = true;
			break;
		}
		m = m->next;
	}
	mutex_unlock();
	if (!leaks_detected) {
		MD_LOG_INFO(MEM_DEBUG_NAME "No memory leaks detected.\n");
		return false;
	}

	MD_LOG_INFO(MEM_DEBUG_NAME "Memory leak summary%s:\n", is_global? "":" (this thread only)");
	mutex_lock();
	m = mem_hdr_base.next;
	while (m) {
		if ((is_global || m->allocator_thread == get_thread_id()) && m->leak_detect_flag) {
			int out_str_o = 0;
			// Show ID of allocating thread.
			out_str_o += snprintf(out_str+out_str_o, MAX_OUT_STR-out_str_o, "T%lu ", m->allocator_thread);
			// Show serial number, global and thread-specific, of this allocation (in different order according to is_global).
			if (is_global) {
				out_str_o += snprintf(out_str+out_str_o, MAX_OUT_STR-out_str_o, "#%u (T#%u): ", m->serial_num, m->serial_num_per_thread);
			}
			else {
				out_str_o += snprintf(out_str+out_str_o, MAX_OUT_STR-out_str_o, "#%u (G#%u): ", m->serial_num_per_thread, m->serial_num);
			}

			// Show address of allocated buffer.
			uint8_t* orig_alloc = (uint8_t*)m + m->prefix_addr_offset + sizeof(void**);
			out_str_o += snprintf(out_str+out_str_o, MAX_OUT_STR-out_str_o, "@%p size 0x%x, content: ", (void*)orig_alloc, m->requested_size);

			// check whether this buffer is text or binary data
			size_t content_dump_size = (m->requested_size < CONTENT_DUMP_MAX_SIZE? m->requested_size : CONTENT_DUMP_MAX_SIZE);
			bool is_text = true;

			if (orig_alloc[0] == 0) {
				is_text = false;
			}
			else {
				for (size_t i=0; i<content_dump_size; i++) {
					if (orig_alloc[i] == '\t' || orig_alloc[i] == '\n' || orig_alloc[i] == '\r') {
						continue;
					}
					if (orig_alloc[i] == '\0') {
						break;
					}
					if (orig_alloc[i] < 32 || orig_alloc[i] > 126) {
						is_text = false;
						break;
					}
				}
			}

			// Show buffer contents - print as string if text, or hex bytes.
			if (is_text) {
				out_str_o += snprintf(out_str+out_str_o, MAX_OUT_STR-out_str_o, "%s", (const char*)orig_alloc);
			}
			else {
				for (size_t i=0; i<content_dump_size; i++) {
					out_str_o += snprintf(out_str+out_str_o, MAX_OUT_STR-out_str_o, "%02x ", orig_alloc[i]);
				}
			}

			// output the string, displaying eol/tabs as escape sequences.
			safe_print_string_escaped(out_str);
			safe_print_string("\n");
		}
		m = m->next;
	}
	mutex_unlock();
	return true;
}

void abort_on_allocation(unsigned int serial_num, unsigned int size, bool is_global) {
	if (is_global) {
		abort_on_global_serial_num = serial_num;
		abort_on_size_global = size;
	}
	else {
		abort_on_thread_serial_num = serial_num;
		abort_on_size_thread = size;
	}
}

uint64_t get_total_alloced_bytes(bool include_padding, bool get_peak, bool is_global) {
	if (is_global) {
		if (get_peak) {
			return (include_padding? global_bytes_alloced_w_padding_max : global_bytes_alloced_max);
		}
		else {
			return (include_padding? global_bytes_alloced_w_padding : global_bytes_alloced);
		}
	}
	else {
		uint64_t ret = 0;
		if (get_peak) {
			ret = (include_padding? thread_bytes_alloced_w_padding_max : thread_bytes_alloced_max);
		}
		else {
			mutex_lock();
			if (thread_specific_info) {
				ThreadSpecificInfo &th = (*thread_specific_info)[get_thread_id()];
				ret = (include_padding? th.thread_bytes_alloced_w_padding : th.thread_bytes_alloced);
			}
			mutex_unlock();
		}
		return ret;
	}
}

void get_largest_thread(int* tid, uint64_t* alloc_size) {
	if (!thread_specific_info) return;
	long int max_tid = -1;
	uint64_t max_alloc = 0;
	mutex_lock();
	for (ThreadSpecificInfoMap::iterator it = thread_specific_info->begin(); it != thread_specific_info->end(); it++) {
		if (it->second.thread_bytes_alloced > max_alloc) {
			max_tid = it->first;
			max_alloc = it->second.thread_bytes_alloced;
		}
	}
	mutex_unlock();
	if (tid) {
		*tid = max_tid;
	}
	if (alloc_size) {
		*alloc_size = max_alloc;
	}
}

uint64_t get_total_mallocs(bool is_global, bool outstanding_only) {
	if (is_global) {
		return (outstanding_only? num_global_allocs : global_num_times_malloc_called);
	}
	else {
		uint64_t ret = 0;
		if (outstanding_only) {
			mutex_lock();
			if (thread_specific_info) {
				ThreadSpecificInfo &th = (*thread_specific_info)[get_thread_id()];
				ret = th.num_thread_allocs;
			}
			mutex_unlock();
		}
		else {
			ret = thread_num_times_malloc_called;
		}
		return ret;
	}
}

void set_memory_limit(uint64_t max_usage) {
	global_bytes_alloced_limit = max_usage;
}

} // namespace

/* C interface */

extern "C" {

void mem_debug_check(const char* file, const int line, const char* user_msg, const int bool_this_thread_only) {
	mem_debug::mem_debug_check(file, line, user_msg, (bool)bool_this_thread_only);
}

void mem_debug_check_ptr(const void* ptr) {
	mem_debug::check_ptr(ptr);
}

void mem_debug_clear_leak_list(int bool_is_global, int bool_restart_serial_nums) {
	mem_debug::clear_leak_list((bool)bool_is_global, (bool)bool_restart_serial_nums);
}

int mem_debug_show_leak_list(int bool_is_global) {
	return (int)mem_debug::show_leak_list((bool)bool_is_global);
}

void mem_debug_abort_on_allocation(unsigned int serial_num, unsigned int size, int bool_is_global) {
	mem_debug::abort_on_allocation(serial_num, size, (bool)bool_is_global);
}

uint64_t mem_debug_get_total_alloced_bytes(int bool_include_padding, int get_peak, int is_global) {
	return mem_debug::get_total_alloced_bytes((bool)bool_include_padding, (bool)get_peak, (bool)is_global);
}

uint64_t mem_debug_get_total_mallocs(int is_global, int outstanding_only) {
	return mem_debug::get_total_mallocs((bool)is_global, (bool)outstanding_only);
}

void mem_debug_set_memory_limit(uint64_t max_usage) {
	mem_debug::set_memory_limit(max_usage);
}

void mem_debug_get_largest_thread(int* tid, uint64_t* alloc_size) {
	mem_debug::get_largest_thread(tid, alloc_size);
}

}

#endif // MEM_DEBUG_ENABLE
