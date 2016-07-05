:title: Introduction to Reverse Engineering
:data-transition-duration: 1500
:css: asm.css

An Introduction to Reverse Engineering

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

