:title: Introduction to Reverse Engineering
:data-transition-duration: 1500
:css: asm.css

An Introduction to Reverse Engineering

----

Intro Static Analysis
=====================

----

Objectives
==========

* Understand and utilize, at a basic level, principles relating to static analysis
* Utilize, at a basic level, IDA Pro for the purpose of static analysis

----

Static Analysis Tools
=====================

* Strings - A very useful tool for dumping things that \*look\* like printable ASCII or Unicode strings
	+ For Windows: Ships with Sysinternals
	+ Linux/Unix: Typically a strings application exists
* Hex Editors - Sometimes useful
* Executable file explorers - CFF Explorer, dumpbin, objdump, otool, etc
	+ Lots of detail about sections and layout of a binary
	+ Will discuss in greater detail in later sections
* Disassemblers - IDA Pro, radare2, etc.
	+ IDA will be our focus for the course
	+ It is an extremely powerful tool, provides lots of useful features for annotating and investigating various binary formats

----

Intro to IDA Pro
================

----

Starting Up
===========

* IDA Allows you to save and load work between sessions via database files
* Annotations and other items can be stored and distributed this way

----

Basic Areas
===========

* Functions Window
* Overview Navigator
* Graph Overview
* Views section

----

Functions Window
================

* IDA will load blocks of code that resemble functions here
* Many of them will initially be named "sub_\*"
	+ Can be renamed later, as functionality is uncovered
	+ A subset may have specific names on load, from symbols, functionality, etc

----

IDA View and Hex View
=====================

* Provides a disassembly view of a section of code
* Can toggle between viewing the disassembly via text view and graph view
* Hex view gives a view in hex bytes, or other formats
	+ Selecting a block of opcodes highlights the whole instruction (if in hex)
	+ Can synchronize selections with IDA View

----

Structures and Enums
====================

* Sections let you define structures and enum values
* Some structure definitions may be populated via type libs and symbols
	+ Many Windows functions and parameters, for example, may be annotated in this fashion

----

Imports and Exports
===================

* Imports indicate libraries and external functions a binary relies on
* Exports denote exported symbols
	+ May identify methods exported for use by other modules
	+ Various other entry points, such as the CRT entry point or TLS callbacks, may appear here
* This topic will be covered in greater depth when discussing executable file formats

----

Useful Features
===============

* XREFS
* Annotations
	+ Comments
	+ Renaming
* Mapping Structure Definitions
* Jump to location

----

XREFS
=====

* Hotkey: x (from IDA View)
* Gives a list of references to an item from the binary
* Double-clicking entries in the list will jump to that location

----

Renaming
========

* Hotkey: n (from IDA View)
* Allows symbols to be renamed as functionality is discovered
	+ Makes it easy to refer back to blocks of code
	+ Functions (in the Functions Window) can also be renamed via right-click and edit (or Ctrl+E)

----

Comments
========

* Hotkey: ; or : (from IDA View)
	+ ; - Repeatable comments
	+ : - Single comment
* Repeatable comments will appear at each occurrence of the symbol
* Single comments will only appear where designated

----

Structure Definitions
=====================

* Hotkey: t (from IDA View)
* Maps a structure definitions (from the Structures tab) to a particular location in memory

----

Jump to Location
================

* Hotkey: enter (from IDA View)
* Jumps the focus of the IDA View window to the definition of the symbol
	+ This includes functions and jump targets
	+ Uninitialized data from other sections in the file (such as .data or .bss) can be viewed in this fashion
	+ As can global constants, such as strings

----

Other Useful Things
===================

* Clicking a symbol or register highlights its use
* Can edit opcodes via hex view
* Can generate a graph of uses for a particular symbol
* Same principles discussed in previous section applies in terms of identifying user-defined entry point

----

Labs 2 & 3
==========

A basic Crack me

Lab 4
=====

From Assembly to C

----

Binary Analysis
===============

----

Objectives
==========

* Discuss and Understand, at a basic level, some strategies for approaching RE
* Understand, at a basic level, some ways of identifying and applying structure to data

----

Looking for Clues
=================

* Imports
* Exports
* Strings

----

Applying Structure to Data
==========================

* Locate data structures in disassembly
* Identify structures, arrays, and constituent data members

----

Structure Identification
========================

.. image:: ./img/yep_its_wood.jpg

----

Structures
==========

* Telltale signs include:
	+ Grabbing a pointer parameter or local variable
	+ Accessing offsets into that variable
	+ Pointer additions/subtractions into a buffer

.. code:: nasm
	
	; Copying a param
	mov edx, [ebp + 8]
	; Loading a value 12 bytes into the buffer
	mov ecx, [edx + 0xC]

----

More Structure Examples
=======================

.. code:: nasm

	mov eax, [ebp + 0x08]
	lea eax, [eax + 0x0c]
	mov edx, [ebp + 0x0c]
	push edx
	push eax
	call _strcpy
	add esp, 0x08

.. code:: c

	struct MyStruct {
		DWORD	firstField;
		DWORD	secondField;
		char	buf[MAX_PATH];
	};

----

Arrays
======

* Same-sized accesses into a buffer might indicate an array
	+ All accesses into the buffer only read or write same sized values
	+ Most structures have some variance in data size
* Other clues might include
	+ Accesses to sequential offsets in a loop
	+ Use of string instructions (e.g., "rep movs\*" or "rep scas\*", etc.)

----

Structures and Arrays
=====================

* Look at how fields are used in other parts of the program
	+ OS-provided function calls with known input params
	+ Other typelib provided function definitions (e.g., static libs)
	+ Make use of xrefs (where possible)
* Annotations are very useful in getting a good feel for control flow

----

Structures and Arrays - Cont'd
==============================

* Applying dynamic analysis can also be useful
* Hardware breakpoints may be especially helpful
	+ If point of allocation can be found, break on read/write can identify what gets copied into the buffer
	+ Various memory printing options (Windbg/gdb) with offsets can also assist with this

----

Finding Allocations
===================

Heap Allocations

* Look for calls to heap allocation methods
	+ malloc/calloc/etc
	+ HeapAlloc
	+ VirtualAlloc 

* Example:

.. code:: nasm

	push 0x30
	call _malloc
	mov dword [eax + 0x08], ecx

----

Finding Allocations
===================

Stack Allocations

.. code:: nasm

	sub esp, 0x30

----

Lab 5
=====

