# MEM_debug - A Quick and Easy Memory Debugger
## Welcome to MEM_debug
MEM_debug is a simple, effective and easy to use heap corruption and memory leak detector. By dropping a single source file into your project you will immediately be able to catch out of bounds writes, double or invalid frees, and information on allocated memory that wasn’t freed. If you suspect a memory corruption bug, a simple API allows you to perform more specific checks during runtime to pinpoint its location. The impact on program performance is minimal.

MEM_debug is not the answer to every problem. There are far more exhaustive solutions but each have their disadvantages: [Valgrind](http://valgrind.org/) is an excellent tool but slows down the program by an order of magnitude, making it unsuitable for real time systems or cases where a problem only appears after a long execution time. [Dmalloc](http://dmalloc.com/) is far more featured but is quite complicated to use.
## Platforms
MEM_debug has been tested on C and C++ projects compiled with GCC under Linux, targeting both Intel and ARM processors.
I’m not sure about other platforms and compilers but glibc is a minimum requirement due to the method used to intercept heap management calls. I’ve had no luck with MacOS or MinGW.

MS Visual Studio offers similar debugging capabilities in its CRT library (see [here](https://docs.microsoft.com/en-us/visualstudio/debugger/crt-debug-heap-details?view=vs-2015) and [here](https://docs.microsoft.com/en-us/visualstudio/debugger/finding-memory-leaks-using-the-crt-library?view=vs-2015)), so this tool wouldn’t be of much help there anyway.

If anyone manages to use MEM_debug on a new platform (perhaps with minor modifications) please let me know.
## Setup
1. Add the files MEM_debug.cpp and MEM_debug.h from this repository to your project, or to one of the shared libs in your project. MEM_debug.cpp should preferably be built with C++11 (or higher) enabled for best results.
2. There is no step 2. Enjoy!
## How it Works
In glibc, heap management functions such as malloc and free are defined as weak symbols, which means they can be overridden by the application or a shared library. After being overridden, the original functions are still accessible via alternate names (\_\_libc_malloc, \_\_libc_free, etc.) so it’s easy to intercept heap functions without needing to completely rewrite them. MEM_debug wraps every allocation with padding bytes before and after the buffer returned to the user, as well as a bookkeeping structure that keeps track of all allocations. The integrity of these wrappings is tested when freeing a buffer, or on demand. The bookkeeping also allows testing for memory leaks.

The functions overridden are: malloc, calloc, valloc, realloc, memalign, posix_memalign, free. Note that ‘new’ and ‘delete’ internally call malloc and free so are covered as well.
## Basic Usage
If you’ve followed the Setup instructions, you will notice that your program now outputs some extra information to the standard output. Suppose we have a program that does nothing in its main() other than call `printf("hello world!\n");`. The program's output will now look like this:
```
** (736) MEM_debug 1.x.x is active.
hello world!
MEM_debug.cpp:170 - At shutdown (peak memory use was 19984 bytes, padded 20428. 3 mallocs, 1 frees): Mem check
OK, 2 allocs, 19968 bytes (padded 20264)
```
The first line is always shown at program start and is intended to let you know MEM_debug is active. The number in parentheses is the process ID.

The last line is automatically output at program exit. It indicates the result of a full heap test. It shows the peak memory use over the lifetime of the process, the total amount of times 'malloc' and 'free' were called, and finally how many outstanding allocations exist and how many bytes remain allocated at program exit. The ‘padded’ values indicate the amount of memory actually allocated, which is higher than what the program requested because it includes the memory allocated for the padding and bookkeeping.

I actually don't know why a program that does nothing reports two unfreed allocations at exit. This is a known issue and I don't know its cause.

Now, let's add an allocation without freeing it: `char* buf = (char*)malloc(10);`

```
** (748) MEM_debug 1.x.x is active.
hello world!
MEM_debug.cpp:170 - At shutdown (peak memory use was 19994 bytes, padded 20586. 4 mallocs, 1 frees): Mem check
OK, 3 allocs, 19978 bytes (padded 20422)
```
As we can see there is now an additional unfreed allocation reported, and 10 extra bytes in the unpadded memory use value.

Now let’s write a garbage value beyond the allocated memory: `buf[10] = 7;`. The result will be:
```
** (759) MEM_debug 1.x.x is active.
hello world!
MEM_debug.cpp:170- At shutdown (peak memory use was 19994 bytes, padded 20586. 4 mallocs, 1 frees): error! write
after allocation - 0x23451c0 (header 0x2345150) Allocated at Apr 22 22:12:54.488 by thread 759 size 10
Segmentation fault
```
What happened here? The shutdown memory test went over all allocations and found that the padding after the user buffer was overwritten. A SIGSEGV signal is raised in this and many other cases, to halt the program and allow you to debug it (when using a debugger) or generate a core dump.

Now suppose we try to free the memory after performing the bad write: `free(buf);`. We will get this:
```
** (772) MEM_debug 1.x.x is active.
hello world!
free: error! write after memory - 0xe181c0
Segmentation fault
```
MEM_debug tests the padding of each buffer when it is freed. So, the problem is caught at this point and the program halts, allowing you to debug it.

For most projects, this could be all you need to find basic heap problems.

Note that MEM_debug can be completely disabled by commenting out the line ‘#define MEM_DEBUG_ENABLE’ near the top of MEM_debug.h.
## Advanced Features
Once dropped in, MEM_debug automatically checks all memory heap operations performed by your process without the need to modify any of your code. However, to use some advanced features an API is supplied. To use it, include the MEM_debug.h header file. Note that when ‘MEM_DEBUG_ENABLE’ is undefined all API calls are replaced with empty stubs. This allows you to easily toggle MEM_debug functionality without having to remove these calls from your code.
### On Demand Memory Check
Memory corruptions can be very difficult to find, often hiding in plain sight in your code. MEM_debug allows you to request a consistency check of the entire heap at any point. This is done by placing the macro MEM_DEBUG_CHECK at the desired location in your code (no semicolon needed). The output of this check will look like this:
```
test.cpp:13: Mem check OK, 4 allocs, 19994 bytes (padded 20586)
```
This shows the file and line number from which the check was called and the result of the test.
In case of an error the result will look like this:
```
test.cpp:18: error! write after allocation - 0x89ad070 (header 0x89ad008) Allocated at Dec 10 22:01:13.277
by thread 22645 size 10
```
The technique for finding the location of a memory corruption is simple: scatter MEM_DEBUG_CHECK in various key points in your program, though not too many that execution would be significantly slowed down. Run the program. At some point a memory check will fail; examine the code between the last success and the failure. If necessary, add more checks within that region of code to narrow down the problematic area. Eventually you will narrow down to the offending line.

The memory checking macro has two additional variants: MEM_DEBUG_CHECK_MSG allows you to specify a custom message that will be shown with the results of that check; MEM_DEBUG_THREAD_CHECK tests only buffers allocated by the current thread, so that in a multithreaded scenario, the thread that halts on an error will (most likely) be the thread responsible for it.

If you don’t want to check the entire heap you may check just a single allocation; this is particularly useful if the corruption always happens to the same allocated buffer and you want to minimize the performance impact of the error checking. To do this call the function mem_debug_check_ptr on the problematic buffer. (C++ users note: this and all other functions are in the ‘mem_debug’ namespace.)
### Leak Detection
MEM_debug allows you to define a code section that will be tested for leaks; when the code completes, it will output a list of all allocations that were performed within the section but not freed. The method of operation is simple: every allocation in the system is marked with a ‘leak’ flag, set to true when allocating. When entering the problematic code section, all leak flags are cleared. When exiting the code section, any allocation now marked as a ‘leak’ must have been allocated within that section but not freed.

Before the code section to be tested, call function mem_debug_clear_leak_list(). After the code section call mem_debug_show_leak_list() and view the results. Here is an example:
```
T10986 #0 (G#0): @0x954d070 size 0xa, content: 00 00 00 00 00 00 00 00 00 00
```
From left to right, this is the information displayed:
- The TID of the thread that allocated this memory.
- The serial number of this allocation within that thread.
- The serial number of this allocation globally (within the process).
- The address of the allocated buffer.
- The size of the buffer.
- The first few bytes of the contents of the buffer. (Strings will be shown as text.)

If this information isn’t enough to pinpoint the leak, check if the serial number of the offending leak is consistent between runs. If it is, you can tell MEM_debug to halt the program on that specific allocation number with mem_debug_abort_on_allocation() and find the offending line in the stack trace.

When debugging a multithreaded program, it is possible to isolate the check to the current thread only, to prevent concurrent allocations from other threads affecting the results. See the MEM_debug.h file for specific instructions on how to do this.
## Tweaks
MEM_debug should work well as is, but a few settings can be modified to help solve your particular issue. The modifiable settings are defined at the beginning of the MEM_debug.cpp file.

- MEM_DEBUG_FILL_ALLOCED_MEMORY - enable this definition to fill every allocated buffer with a set pattern. This helps catch use of uninitialized memory.
- MEM_DEBUG_FILL_FREED_MEMORY - enable this to fill every freed buffer with a set pattern. This helps catch attempts to use memory that has recently been freed.
- PREFIX_SIZE and SUFFIX_SIZE - set the size of the padding used for protecting against out of bounds memory writes. The default should be enough for off-by-one or other minor errors, but can be changed if desired.
- PAD_CHAR - this is the byte used to fill the memory padding, or the entire buffer if MEM_DEBUG_FILL_ALLOCED_MEMORY is set.
- PAD_FREEMEM_CHAR - this is the byte used to fill freed memory if MEM_DEBUG_FILL_FREED_MEMORY is set.
- MAX_ALLOC - catch unintentional huge allocations by setting a limit on a single allocation. The default is quite large but if you want to allocate something larger feel free to change it.
- MD_LOG_INFO, MD_LOG_WARNING, MD_LOG_ERROR - these are used by the diagnostic functions to output their reports. They are mapped to ‘printf’ by default but can be set to your own logging functions as desired. Note that errors that may occur during critical sections are output by direct writes to stderr and will not be affected by this.
## FAQ
Nothing here yet.
## Contact
Feel free to contact the author, Itay Chamiel, itaych at gmail.com with questions, remarks or suggestions. If you are successfully using MEM_debug in a major project I will be happy to hear about it!
## License
This software is provided 'as-is', without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.

Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product or in the course of product development, an acknowledgment in the product documentation would be appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
## Acknowledgments
Thanks to Stack Overflow user Andreas Grapentin for the [description](http://stackoverflow.com/questions/17803456/an-alternative-for-the-deprecated-malloc-hook-functionality-of-glibc) of the basic method used to intercept heap management functions.
Thanks to my managers at [OrCam](http://www.orcam.com/) for allowing me to release this tool which I developed at work for internal use.
