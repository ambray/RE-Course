:title: Introduction to Reverse Engineering
:data-transition-duration: 1500
:css: asm.css

An Introduction to Reverse Engineering

----

Intro to Reverse Engineering
============================

* TODO: clever intro title here

----

Course Roadmap
==============

* TODO: clever roadmap thing here

----

Introduction
============

Beginning RE

----

Objectives
==========

* Understand the basic goals of RE
* Introduce various types of analysis

----

Reverse Engineering
===================

* Process of determining how a program (or set of programs) works (typically without access to source code)
* 

----

Intro Dynamic Analysis
======================

----

Objectives
==========

* Understand and utilize, at a basic level, principles relating to dynamic analysis
* Utilize, at a basic level, Windbg for the purpose of dynamic analysis
* Utilize, at a basic level, the Sysinternals tools for the purpose of dynamic analysis

----

Intro Static Analysis
=====================

----

Objectives
==========

* Understand and utilize, at a basic level, principles relating to static analysis
* Utilize, at a basic level, IDA Pro for the purpose of static analysis

----

Compilers - an Introduction
===========================

----

Objectives
==========

* Understand fundamental concepts pertaining to how the compilation process works
* Understand and identify security mechanisms implemented by compilers
* Understand and identify some minor optimizations performed by compilers
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

Compiler Security Features
==========================

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

* Microsoft specific
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

	0xcc 0xcc 0xcc 0xcc 0xcc	; the prologue
	0x89 0xff					; the patch point


After:

.. code:: objdump-nasm

	0xe9 0xf3 0xf9 0xff 0xff	; the jmp newloc bytes
	0xeb 0xf9					; the short jmp

----

Windows Internals Primer
========================

----

Objectives
==========

* Understand HANDLEs and some of their uses
* Understand the Windows Object Manager, and how it relates to various kernel objects
* Understand the general memory layout and composition of a Windows process

----

Binary Analysis
===============

----

Objectives
==========

* Understand and utilize a combination of static and dynamic analysis to perform RE
* Investigate more advanced features of previously mentioned tools, such as procmon, Windbg, and IDA Pro

----

Executable File Formats
=======================

----

Objectives
==========

* Understand and Identify the major components of executable file formats
	+ PE
	+ ELF
	+ MACH-O
* Analyze the composition of provided binaries

----

Loading and Linking
===================

----

Objectives
==========

* Understand, at a high level, the process of loading and running executables
* Understand some of the action performed by the C Runtime (CRT) during initialization

----

Analysis Triage
===============

----

Objectives
==========

* Using a combination of static and dynamic analysis techniques, locate interesting items in provided binaries

----

Compilers - Optimizations
=========================

----

Objectives
==========

* Understand and identify a number of optimizations performed by compilers

----

C++ From a Binary Perspective
=============================

----

Objectives
==========

* Understand and Identify Run Time Type Information (RTTI), and its uses
* Understand and Identify C++ Class Layouts in memory
* Understand how Inheritance Affects C++ in-memory structure
* Understand the composition of C++ class memory functions and vtables
* Understand and Identify the affect of C++ Templates on generated code

----

Additional Topics
=================

As time permits...

----

Objectives
==========

* Rust
* Go
* SEH
* Crypto Constants
* Anti-debugging techniques
* Forensics?
* ??

----

Review
======
