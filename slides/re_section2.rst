:title: Introduction to Reverse Engineering
:data-transition-duration: 1500
:css: asm.css

An Introduction to Reverse Engineering

----

Compilers - an Introduction
===========================

----

Objectives
==========

* Understand fundamental concepts pertaining to how the compilation process works
* Understand and identify security mechanisms implemented by compilers
* Understand and identify some features and minor optimizations performed by compilers
* Understand and identify intrinsic methods

----

The Compilation Process
=======================

* How do we get from a text file to a binary?

----

Lexing: The First Step
======================

* Text is broken into tokens
* The "how" is based on language contraints  (e.g., whitespace, semicolons, etc)

----

Parsing
=======

* The next step in interpreting text
* Stream of tokens created from lexing are examined here
* Abstract Syntax Tree (AST) gets built from this

----

Where too from here?
====================

* Several transformations typically applied
	+ the original AST gets changed a bit, losing context
	+ Sometimes something that resembles a pseudo-assembly gets produced here (e.g., llvm ir)
	+ Typically still has more "intent" (e.g., what the programmer intended to do) encoded than raw assembly/opcodes
* Optimizations get added here
* Register spills and variable lifecycle gets analyzed/calculated at this point

----

\... And out comes a binary?
============================

* Various sections get generated (more on this topic later)
* Compilation finishes, assembly gets produced, and assembling happens
* Object files get created
* Linking occurs

And finally....

* A binary gets created!

----

Compiler Features
=================

* A number of security features exist (and are now usually implemented by default) for compilers
* Some are specific to vendors/file formats

----

Stack Canary
============

* A "cookie" that is added to the stack inside of a function call to indicate that the stack has been corrupted
* Generally set at function prologue (on stack)
* Typically checked just prior to function return

----

Stack Canary
============

.. image:: ./img/stackcookie.png

----

Relocations
===========

* PE-specific
* Provide information to fix up addresses on load (more on this topic later)
* Makes PE files (which are not position-independent) work with ASLR

----

Patch Points
============

* Microsoft originated
* GCC extension - ms_hook_prologue - will provide
* Implementation that allows for hotpatching
* Provides a 2-bytes, idempotent function prelude that can overwritten with a jmp
* Typically preceded by a 5 byte (in x86, anyhow), writable area to add a bigger jmp

----

Patch Point
===========

.. code:: nasm

	; patchable area... 5 bytes of space
	winfunc:
		mov edi, edi ; two byte reserved patch point

After patch:

.. code:: nasm
	
	patched:
		jmp newloc	; 5-byte jump to real destination
	winfunc:
		jmp	patched	; 2-byte relative jump (backward)

----

Patch Point (cont'd)
====================

Looking at disassembled bytes we'd get something like:


Before:

.. code:: objdump-nasm

	0xcc 0xcc 0xcc 0xcc 0xcc  ; the prologue
	0x89 0xff				  ; the patch point


After:

.. code:: objdump-nasm

	0xe9 0xf3 0xf9 0xff 0xff  ; the jmp newloc bytes
	0xeb 0xf9				  ; the short jmp

----

Intrinsic Functions
===================

* Intrinsic functions are special functions implemented directly by the compiler
* Intrinsic offerings vary by compiler
* They typically map directly to a small number of assembly instructions
* Typical use cases are to expose functionality provided by assembly that doesn't exist in the C (or C++) standard library, such as access to SIMD operations.

----

Intrinsic Functions (cont'd)
============================

Example (Microsoft):

.. code:: c++

	__debugbreak();

maps directly to:

.. code:: nasm

	int3

----

Intrinsic Function (cont'd)
===========================

Comprehensive lists for supported intrinsic functions should be provided as part of compiler documentation

* MSDN: https://msdn.microsoft.com/en-us/library/26td21ds.aspx
* GCC (4.2.4): http://gcc.gnu.org/onlinedocs/gcc-4.2.4/gcc/X86-Built_002din-Functions.html
* Clang: http://clang.llvm.org/docs/LanguageExtensions.html#introduction

----

Compiler-implemented Functions
==============================

* A number of common functions may be implemented directly by the compiler inline
* Methods such as strlen, memcpy, etc may fall into this category
* As such, disassembly may not contain a "call" to these methods, but rather something like:

.. code:: nasm

	mov ecx, 0x30
	mov esi, [ebp - 0x0c]
	mov edi, [ebp + 0x08]
	rep movsb

in place of memcpy

----

Lab 5
=====


----

Windows Internals Primer
========================

----

Objectives
==========

* Understand basic facts relating to the Windows API
* Understand HANDLEs and some of their uses
* Understand the Windows Object Manager, and how it relates to various kernel objects
* Understand the general memory layout and composition of a Windows process
* Understand, at a basic level, the purpose of some common kernel object types

----

Windows API Basics
==================

* The Windows API is broken into a series of layers
* Win32 API provides the bulk of the "documented" functionality provided to developers
* The Windows Native API exists a layer down from the Win32 API, and underpins its functionality

----

The Win32 API
=============

* Covers the bulk of the documented APIs provided to developers
* Spans a number of DLLs and libraries
* General Purpose Methods
	+ Many provided via Kernel32.dll
	+ Post Windows XP, implementation provided in KERNELBASE.dll
* Other DLLs of Note
	+ User32.dll - Provides Most GUI methods
	+ Ws2_32.dll - Networking Functions

----

ASCII vs Unicode
================

* A large number of Win32 methods are provided in two forms:
	+ ASCII
	+ Wide character (UTF-16le)
* In these cases, two versions are exported from the parent DLL.

Example:

* Kernel32 exports two versions of CreateFile
	+ CreateFileA - Accepts an ASCII file path (char\*)
	+ CreateFileW - Accepts a wide char file path (wchar_t\*)

----

The Windows Native API
======================

* Underpins the Win32 API Methods
* Largely undocumented
* Exposes some additional functionality not available via Win32 methods
* Primarily exported from ntdll.dll

----

Native API Methods and References
=================================

* Some methods documented via the Windows Driver Kit docs
* Nt\* and Zw\* Methods are the same in user mode (though not in kernel mode)
* See also: Windows NT/2000 Native API Reference by Gary Nebbett

----

Unicode and the Native API
==========================

* Almost all native API methods exclusively use wide-character strings
* UNICODE_STRING structure is used throughout Native API and Kernel API
* UNICODE_STRINGs are byte counted, and not always NULL terminated

----

WoW64
=====

* Stands for Windows on Windows 64
	+ Set of facilities for managing 32 bit programs on 64 bit systems
	+ 64 bit system path:  C:\Windows\System32
	+ 32 bit emulated path: C:\Windows\SysWOW64
* Registry Entries also redirected: wow6432node

----

Differences in Entry Points
===========================

* Console Applications:

.. code:: c

	int main(int argc, char** argv)
	/* WCHAR == wchar_t */
	int wmain(int argc, WCHAR** argv)

* GUI Applications:

.. code:: c

	/**
	*  LPWSTR == wchar_t* 
	*  LPSTR == char*
	*  HINSTANCE == HANDLE
	*/
	int CALLBACK WinMain(HINSTANCE hInst,
	                     HINSTANCE hPrev,
	                     LPSTR     lpCmdLine,
	                     int       nCmdShow)
	int CALLBACK wWinMain(HINSTANCE hInst,
	                      HINSTANCE hPrev,
	                      LPWSTR     lpCmdLine,
	                      int       nCmdShow)

----

Differences in Entry Points
===========================

* DLLs

.. code:: c
	
	/* LPVOID == void* */
	BOOL WINAPI DllMain(HINSTANCE hInst, 
	                    DWORD dwReason, 
	                    LPVOID lpReserved)

* Drivers

.. code:: c

	NTSTATUS DriverEntry(PDRIVER_OBJECT pDrv, 
	                     PUNICODE_STRING pRegPath)

----

The Windows Object Manager
==========================

* Kernel-mode entity responsible for managing kernel objects
* Maintains a reference (and HANDLE) count of each object
* Handles garbage collection of objects when all consumers have stopped using resources

----

Why does this matter?
=====================

* All of those kernel objects map to resources in use by various processes
* From an RE perspective, this (potentially) gives a great deal of insight into what sort of things a process might be doing
* Resources are (relatively) easily enumerable via sysinternals tools (e.g., Process Explorer)

.. note:: 

	perform procexp demo -> Show lower pane to make kernel objects used by process visible

----

What's in a HANDLE?
===================

* Intentionally opaque structure
* Pointer-size (though typically not really a pointer)
* Actually represents an offset into a process's HANDLE table

----

HANDLEs (cont'd)
================

* HANDLE table provides a simple way for the Object Manager to keep track of process resources
* Each object stored in the table essentially brokers access to various kernel objects (subject to permissions, of course)
* Some Examples of kernel objects:
	+ A HANDLE to a MUTEX
	+ A File Object, representing a file (or device) currently opened by the process
	+ A HANDLE to another process
	+ ...
* The HANDLE table of a given process can be dumped via Windbg using the !handle extension

.. note:: 

	Demo: dump the handles of a process using Windbg

----

HANDLEs and pseudo-HANDLEs
==========================

* Pseudo-HANDLEs are similar (at first glance) to HANDLEs, in that they are opaque (and often typedef'd to HANDLE), but do not have all of the same properties
* CloseHandle typically cannot be called on a pseudo-HANDLE
* Some examples include:
	+ The context HANDLE returned by FindFirstFile(A|W)
	+ The return value of GetModuleHandle() (which is actually the base address of the requested module)

----

Windows Kernel Objects
======================

* Variety of object types
* Can be viewed via Sysinternals tools/Windbg
* Can be named or unnamed
* Various namespaces exist (\\??\\, \\Devices, etc.)

----

Kernel Object Types
===================

Some common types that can be observed:

* Sections
	+ Represent a block of memory
	+ Can be regularly allocated, memory mapped file, etc
* Ports
	+ Often represent (A)LPC Communication mechanisms
	+ Used for IPC

----

Kernel Object Types (cont'd)
============================

* Mutants
	+ Another name for MUTEXes
	+ As kernel objects, can provide cross-process synchronization
* Events
	+ Another synchronization/signaling mechanism
* File Objects
	+ Represents an open instance of another object, such as a file, directory, or device
* Many others

----

Process Bookkeeping
===================

* Much of the usermode process bookkeeping information is available via a number of undocumented/partially documented (but easily reachable) structures
* The Thread Information Block (TIB) and Thread Environment Block (TEB) exist on a per-thread basis
* The Process Environment Block (PEB) exists per process

----

TIB and TEB
===========

* The TIB is actually a subset of the TEB (the first field, in fact!)
* Lots of per-thread information is tracked here, to include the last error value (accessed via (Get|Set)LastError), and the Thread Local Storage table (We'll talk more about TLS when we discuss executable file formats)
* Useful parts of the TIB and the TEB
* (windbg) !teb
* (windbg) dt -r nt!_TEB

----


PEB
===

* Containts quite a bit of useful information, including links to the list of loaded DLLs, the debug port, and other various resources
* Useful parts of the PEB
* (windbg) !peb
* (windbg) dt nt!_PEB

----

The PEB and Changes
===================

 * Some variations to the structure, but many parts remain the same
 * Good writup of the PEB's makeup, both current and historical:

 http://blog.rewolf.pl/blog/?p=573

----

Dynamic and Runtime Linking
===========================

----

Objectives
==========

* Understand and utilize Dynamic and Runtime loading techniques
* Understand and utilize Dynamic and Runtime linking techniques

----

What is Dynamic Linking?
========================

* Allows binary data to be distributed as a DLL or Shared Object file
	+ Has the same general attributes as a standard executable  (including the same file format)
	+ Provides common library services for multiple executables without having to increase size as much as static linking
* Typically requires a static library and a header file
* Loaded into process space at runtime, as part of dependency resolution
	+ When target executable is run, its imports are examined by the operating system
	+ Dynamic libraries it depends on are loaded prior to execution
* Most (read: nearly all) applications implicitly do this in one way or another
	+ C(++) Runtime code is often dynamically linked (e.g., glibc)
	+ Ancillary, OS-provided code (e.g., kernel32) works in this fashion also
* Loading will fail if the required dynamic library is not present

----

Runtime Linking
===============

* Similar to dynamic linking, but with a key difference
	+ No extra lib/header generally required
	+ Onus is entirely on end user (e.g., the executable) to ensure that things go smoothly when loading/linking
* Exported functions must be located by end user
	
----

Runtime Linking - How to load a library
=======================================

* Windows
	+ LoadLibrary(A|W) - Provides the interface for loading a DLL from disk into the current process
	+ GetProcAddress  - Given an HMODULE (returned by LoadLibrary or GetModuleHandle), it will attempt to locate an exported function.
* Linux
	+ dlopen - Similar in function to LoadLibrary, it will load a shared object into the current process.
	+ dlsym - As with GetProcAddress, it will attempt to locate an exported symbol on the provided library

----

Windows Exports
===============

* Can be exported either by name or ordinal
	+ Name - string; may (or may not) be mangled according to calling convention
	+ Ordinal - Simply a number - Must be WORD-sized or smaller
* Both are really just methods of finding exported symbols
* Exports can also forward to other DLLs

----

Windows - Loading a Library
===========================

.. code:: c

	int main(int argc, char** argv)
	{
		// Our module
		HMODULE hm = NULL;
		// Our dynamic function pointer
		int (__stdcall *dynamicFunction)(int) = NULL;
		int result = 0;

		// try to dynamically load our library, fail and return if we can't find it!
		if(NULL == (hm = LoadLibraryA("MyLib.dll"))) {
			printf("We failed to load our library! %d\n", GetLastError());
			return -1;
		}
		// Try to find our dynamic function... this requires us to do a crazy cast.
		// If it were exported by ordinal, the string "MyFunction@4" would change to: (char*)n,
		// where n is the ordinal number. This is a bit strange (to say the least), but the way the
		// API works.
		if(NULL == (dynamicFunction = (int(__stdcall*)(int))GetProcAddress(hm, "MyFunction@4"))) {
			printf("Failed to find MyFunction! %d\n", GetLastError());
			return -2;
		}
		// Now we call our function, and FreeLibrary (since we are done with it now)
		result = dynamicFunction(10);
		FreeLibrary(hm);

		return result;
	}

----

Linux - Loading a Library
=========================

.. code:: c

	int main(int argc, char** argv)
	{
		void* hm = NULL;
		int(*myexport)(int) = NULL;
		int result = 0;
		// As with loadlibrary, we pass the path to load
		if(NULL == (hm = dlopen("./mylib.so", RTLD_NOW))) {
			printf("Failed to find our lib! %s\n", strerror(errno));
			return errno;
		}
		// again, we get our function pointer
		if(NULL == (myexport = (int(*)(int)))dlsym(hm, "myExportedFunction")) {
			printf("Failed to find our function! %s\n", strerror(errno));
			return errno;
		}
		// call and close!
		result = myexport(10);
		dlclose(hm);

		return result;
	}

----

Lab - Runtime Linking
=====================

// TODO: Finish windows lab