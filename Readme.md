# Introduction / tl;dr

This script scans an executable file for Delphi virtual function tables. It 
outputs a JSON file with information about identified classes and functions.

The JSON can be used for additional analysis, for example:

* Generate a class tree.
* Generate names & comments for IDA.
* Feed into further processing, e.g. automatic decompilation.

Some caveats:

* Only supports 32-bit code at this time.
* Only supports Windows PE files (Delphi will compile to other formats).
* Only supports older vftables at this time (as it was primarily written for
  malware analysis, where Delphi 2005 is frequently used).
* Not designed to be a full Delphi decompiler.  Use DeDe / IDR / Hex-Rays.
* Only useful with Delphi binaries that use OOP (not all do).

# How it works

* Identify potential vftables & validate them
* Parse out the name and relationships
* Identify function inheritance

## Idenfiying potential vftables

Delphi vftables are well documented.  Information for the latest version is 
[available from Embarcadero](http://docwiki.embarcadero.com/RADStudio/Seattle/en/Internal_Data_Formats).  
Unofficial documentation is available for Delphi 2005 ([see here](http://pages.cs.wisc.edu/~rkennedy/vmt)).

The first item in a vftable is `vmtSelfPtr`, which points to the start of the 
virtual function table.  The script scans each code segment in the PE file for
any location pointing forward +0x4C.  Note that the Delphi compiler aligns
vftables to a 4 byte boundary (for optimisation).

For example, the following VA 0x0046E1C8 contains the offset 0x0046E214, which
is 0x4C ahead of the current location.

    .text:0046E1C8                   ; Classes::TComponent *vftable_TDCP_misty1
    .text:0046E1C8 14 E2 46 00       vftable_TDCP_misty1 dd offset off_46E214

This approach can generate false positives, therefore other fields in the 
vftable are checked for sensible values.  For example the `vmtInstanceSize`
is checked to ensure it isn't excessive and function pointers are verified to
lie in an executable section.

## Inheritance

Each function found in a vftable is checked to see if it is inherited from the 
parent or overloaded.  Delphi does not support multiple inheritance so this can
be achieved by checking the pointer in the parent vftable with the same offset.

If both pointers reference the same function it is inherited.  If the child has
a different pointer then it has been overloaded.

# Example output



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

# Future aims

* Identify the Delhi version (e.g. from `PACKAGEINFO` or `DVCLAL` resource) and 
  adjust scanning for different vftable layouts.
* Parse more class information, e.g. properties (a Delphi specific)
* Parse Delphi RTTI information (vmtTypeInfo in the vftable)
* Disassemble code with Capstone and identify virtual calls (e.g. match call [ecx+3Fh] to an instance method)

# Caveats

