# Introduction / tl;dr

This tool scans an executable file for Delphi data, including RTTI and virtual
function tables.  It outputs a JSON file with information about identified
classes and functions, which can be used for additional analysis, for example:

* Generate a class tree.
* Generate names & comments for IDA.
* Feed into further processing, e.g. automatic decompilation.

An IDAPython script that can load the output into IDA is provided.

The script was written to complement other tools for reverse engineering
Delphi.

# Author & license

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by David Cannings (@edeca) david.cannings@nccgroup.com

http://www.github.com/nccgroup/pythia

This project is released under the AGPL license. Please see LICENSE for more information.

# How it works

The high level flow is:

* Load a PE file and find code sections
* Scan through each code section 4 bytes at a time
* Identify potential vftables & validate them
* Parse out the class name and parent relationships
* Identify function inheritance

## Idenfiying potential vftables

Delphi vftables are well documented.  Information for the latest version is 
[available from Embarcadero](http://docwiki.embarcadero.com/RADStudio/Seattle/en/Internal_Data_Formats).
Unofficial documentation is available for Delphi 2005 ([see here](http://pages.cs.wisc.edu/~rkennedy/vmt)).

The source code for Free Pascal is also useful ([Github mirror](https://github.com/graemeg/freepascal)).

An older [IDC script](https://github.com/Eadom/Compiler-Internals--Exceptions-and-RTTI/blob/master/typeinfo/Delphi_Typeinfo.idc) is available from Igor Skochinsky which details default methods in various Delphi versions.

The first item in a vftable is `vmtSelfPtr`, which points to the start of the
virtual function table.  The script scans each code segment in the PE file for
any location pointing forward `+0x4C` bytes.  Note that the Delphi compiler aligns
vftables to a 4 byte boundary (for optimisation).

For example, the following VA `0x0046E1C8` contains the offset `0x0046E214`, which
is `0x4C` ahead of the current location.  As shown in IDA:

    .text:0046E1C8                   ; Classes::TComponent *vftable_TDCP_misty1
    .text:0046E1C8 14 E2 46 00       vftable_TDCP_misty1 dd offset off_46E214

This approach can generate false positives, therefore other fields in the
vftable are checked for sensible values.  For example the `vmtInstanceSize`
is checked to ensure it isn't excessive and function pointers are verified to
lie in an executable section.  During testing the false positive rate was
very low, despite the brute force search method.

## Inheritance

Each function found in a vftable is checked to see if it is inherited from the 
parent or overloaded.  Delphi does not support multiple inheritance so this can
be achieved by checking the pointer in the parent vftable with the same offset.

If both pointers reference the same function it is inherited.  If the child has
a different pointer then it has been overloaded.

# Example output

The primary output from the tool is a JSON file which can be fed into subsequent
processing / tools.  However, a few other output formats are included.

## Tree output

Use the `--save-tree` option to generate a file like:

    TObject (at 0x0040112c)
    |-- Exception (at 0x004081f8)
    |   |-- EAbort (at 0x00408260)
    |   |-- EAbstractError (at 0x00408ad4)
    |   |-- EAssertionFailed (at 0x00408a74)
    |   |-- EBcdException (at 0x004bd110)
    |   |   +-- EBcdOverflowException (at 0x004bd16c)
    |   |-- EBitsError (at 0x0041ab04)
    |   |-- EComponentError (at 0x0041abbc)
    |   |-- EConvertError (at 0x00408850)
    |   |-- EDCP_cipher (at 0x0046a0ac)
    |   |   +-- EDCP_blockcipher (at 0x0046a29c)
    |   |-- EDCP_hash (at 0x00469f20)
    .. etc ..

# Supported Delphi versions

The current aim is for this tool to support Delphi version 3 (released 1997) and above.  A number of changes would be required for Delphi 2 (released 1996).

There is no aim to support other compilers, e.g. FreePascal, however this could be investigated if required.

# Future aims

* Identify the Delhi version (e.g. from `PACKAGEINFO` or `DVCLAL` resource) and adjust scanning for different vftable layouts.
* Parse more class information, e.g. properties (a Delphi specific item) and method tables
* Parse Delphi RTTI information (vmtTypeInfo in the vftable)
* Disassemble code with Capstone and identify virtual calls (e.g. match `call [ecx+3Fh]` to an instance method)

## Ideas for identifying Delphi version

Inspect the unit initialisation table and check the size of header.  Delphi >=2010 have a larger offset than previous versions.

Inspect the size of vftables (if possible?) to see how large the offsets are.

# Caveats

* Only tested on 32-bit code at this time.  Please send me 64 bit samples.
* Only supports Windows PE files (Delphi will compile to other formats).
* Not designed to be a full Delphi decompiler.  Use DeDe / IDR / Hex-Rays.
* Only useful with Delphi binaries that use objects (not all do).
* Modern Delphi uses names like `TComparer<System.Bindings.EvalProtocol.TPair<System.IInterface,System.Pointer>>` which are fairly indecipherable in IDA.
* Not designed to process packed files.  Unpack and dump to a regular PE file first.

Please send me examples of binaries where this tool doesn't work, so it can
be improved.
