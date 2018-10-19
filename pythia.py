# vim: autoindent expandtab tabstop=4 shiftwidth=4 softtabstop=4
# filetype=python

from __future__ import print_function
from binascii import hexlify
from construct import *
from struct import unpack_from
from treelib import Node, Tree
#import collections
import logging
import argparse
import pefile
import sys
import os
import io
import treelib
import yaml
import json
import struct

########
#              _   _     _
#  _ __  _   _| |_| |__ (_) __ _
# | '_ \| | | | __| '_ \| |/ _` |
# | |_) | |_| | |_| | | | | (_| |
# | .__/ \__, |\__|_| |_|_|\__,_|
# |_|    |___/
#
# pythia is a tool to extract RTTI information from portable executables
# compiled by Delphi.  See Readme.md.
#
# Author: David Cannings (@edeca)
#   Date: January 2017 (first PoC), October 2018 (release)
########

# TODO: Switch to using Python logging module instead of print

# TODO: Change into a class that can be imported
# TODO: Bundle as a module
# TODO: Allow the user to initialise with a pe=pefile object instead of filename
# TODO: Consider storing a list of known GUIDs
# TODO: Investigate whether parse_stream and seek is more efficient than
# lots of slices

# See https://theroadtodelphi.com/category/delphi/rtti/
types = Enum(Byte,
                 tkUnknown=0,
                 tkInteger=1,
                 tkChar=2,
                 tkEnumeration=3,
                 tkFloat=4,
                 tkString=5,
                 tkSet=6,
                 tkClass=7,
                 tkMethod=8,
                 tkWChar=9,
                 tkLString=10,   # 0x0A
                 tkWString=11,   # 0x0B
                 tkVariant=12,   # 0x0C
                 tkArray=13,     # 0x0D
                 tkRecord=14,    # 0x0E
                 tkInterface=15,  # 0x0F
                 tkInt64=16,     # 0x10
                 tkDynArray=17,  # 0x11
                 tkUString=18,   # 0x12
                 tkClassRef=19,  # 0x13
                 tkPointer=20,   # 0x14
                 tkProcedure=21,  # 0x15
                 )

method_type = Enum(Byte,
                   mkProcedure=0,
                   mkFunction=1,
                   mkConstructor=2,
                   mkDestructor=3,
                   mkClassProcedure=4,
                   mkClassFunction=5,
                   mkClassConstructor=6,
                   mkOperatorOverload=7,
                   mkSafeProcedure=8,
                   mkSafeFunction=9,
                   )

ordinal_type = Enum(Byte,
                    otSByte=0,
                    otUByte=1,
                    otSWord=2,
                    otUWord=3,
                    otSLong=4,
                    otULong=5,
                    )

float_type = Enum(Byte,
                  ftSingle=0,
                  ftDouble=1,
                  ftExtended=2,
                  ftComp=3,
                  ftCurr=4,
                  )

guid = Struct(
    "Data1" / Bytes(4),
    "Data2" / Bytes(2),
    "Data3" / Bytes(2),
    "Data4" / Bytes(2),
    "Data5" / Bytes(6),
)

type_property = Struct(
    "ParentPtr" / Int32ul, # PPTypeInfo
    "GetProcPtr" / Int32ul,  # Might not always be a pointer, e.g. 0xFF00005C
    "SetProcPtr" / Int32ul,  # Same as GetProcPtr
    "StoredProcPtr" / Int32ul,
    "Index" / Int32ul,
    "Default" / Int32ul,
    "NameIndex" / Int16ul,
    "Name" / PascalString(Byte, 'ascii'),
)

typeinfo_tkEnumeration = Struct(
    "OrdType" / ordinal_type,
    "MinValue" / Int32ul,
    "MaxValue" / Int32ul,
    "BaseTypePtr" / Int32ul,  # PPTypeInfo
    # "Values" / Array(this.MaxValue + 1, PascalString(Byte, 'ascii')), # We can't parse this until we've resolved parent relationships - as the values may be attached to the parent
    #"UnitName" / PascalString(Byte, 'ascii'),
    # Potentially 2 bytes (WORD) of extra data length?
)

typeinfo_tkClass = Struct(
    "ClassPtr" / Int32ul,
    "ParentPtr" / Int32ul,  # PPTypeInfo for parent
    "unk1" / Bytes(2),
    "UnitName" / PascalString(Byte, 'ascii'),
    "NumProps" / Int16ul,
    "Properties" / Array(this.NumProps, type_property),
)

typeinfo_tkDynArray = Struct(
    "Size" / Int32ul,  # PtrUInt?  Seems wrong, more likely to be UInt?
    "ElementTypePtr" / Int32ul,  # PPTypeInfo
    "Type" / Int32ul,
    "ElementType2Ptr" / Int32ul,  # PPTypeInfo - TODO what is this?
    "UnitName" / PascalString(Byte, 'ascii'),
    "unk5" / Int32ul,  # PPTypeInfo (usually same as unk4?)
    # Potentially some more unknown bytes follow
)

typeinfo_tkInt64 = Struct(
    "MinValue" / Int64sl,
    "MaxValue" / Int64sl,
    "NumExtra" / Int16ul,
    "Extra" / Bytes(this.NumExtra - 2),
)

typeinfo_tkFloat = Struct(
    "FloatType" / float_type,
    "NumExtra" / Int16ul,
    "Extra" / Bytes(this.NumExtra - 2),
)

typeinfo_tkPointer = Struct(
    "TypeinfoPtr" / Int32ul,
    # Possibly 2 bytes (WORD) of extra data length?
)

typeinfo_tkClassRef = Struct(
    "TypeinfoPtr" / Int32ul,
    # Possibly 2 bytes (WORD) of extra data length?
)

typeinfo_tkInterface = Struct(
    "ParentPtr" / Int32ul,  # PPTypeInfo
    "unk1" / Byte,  # Possibly HasGuid (official docs)
    "Guid" / guid,
    "UnitName" / PascalString(Byte, 'ascii'),
    "unk2" / Int32ul,
    # Possibly 2 bytes (WORD) of extra data length?
)

typeinfo_tkArray = Struct(
    "unk1" / Int32ul,
    "unk2" / Int32ul,
    "TypeinfoPtr" / Int32ul,
    "unk3" / Bytes(5),
    "NumExtra" / Int16ul,
    "Extra" / Bytes(this.NumExtra - 2),
)

typeinfo_tkProcedure = Struct(
    "unk1" / Int32ul,  # Points to another structure - TODO
    "NumExtra" / Int16ul,
    "Extra" / Bytes(this.NumExtra - 2),
)

# Generic type for types that only have attribute data, which
# is undocumented.
typeinfo_AttrDataOnly = Struct(
    "NumExtra" / Int16ul,
    "Extra" / Bytes(this.NumExtra - 2),
)

# Generic type for integers and character types
typeinfo_NumCharTypes = Struct(
    "OrdType" / ordinal_type,  # Min/Max type depends on this (signed/etc)
    "MinValue" / Int32sl,  # TODO: Convert this based on OrdType
    "MaxValue" / Int32sl,
    # Possibly 2 bytes (WORD) of extra data length?
)

# Identifies an AnsiString type
typeinfo_tkLString = Struct(
    "unk1" / Bytes(6),
    "Codepage" / Int16ul,
    "unk2" / Int32ul,
    "unk3" / Int32ul,
    # Possibly 2 additional bytes, need to check
)

typeinfo_method_param = Struct(
    "unk1" / Byte,
    "ParamName" / PascalString(Byte, 'ascii'),
    "TypeName" / PascalString(Byte, 'ascii'),
)

typeinfo_tkMethod = Struct(
    "MethodType" / method_type,
    "NumParams" / Byte,
    "Params" / Array(this.NumParams, typeinfo_method_param)
)

typeinfo_tkSet = Struct(
    "unk1" / Byte,
    "TypeinfoPtr" / Int32ul,  # Pointer to pointer
    # Possibly 2 bytes (WORD) of extra data length?
)

typeinfo_managedfield = Struct(
    "unk1" / Int32ul,
    "unk2" / Int32ul,
)

typeinfo_record = Struct(
    "TypeinfoPtr" / Int32ul,
    "Offset" / Int32ul,  # Probably offset from something, increments
    "unk1" / Byte,
    "Name" / PascalString(Byte, 'ascii'),
    "NumExtra" / Int16ul,
    "Extra" / Bytes(this.NumExtra - 2),
)

typeinfo_tkRecord = Struct(
    "RecordSize" / Int32ul,  # From Embarcadero docs
    "NumManagedFields" / Int32ul,  # From Embarcadero docs
    "ManagedFields" / Array(this.NumManagedFields, typeinfo_managedfield),
    "unk1" / Byte,
    "NumRecords" / Int32ul,
    "Records" / Array(this.NumRecords, typeinfo_record),
)

typeinfo = Struct(
    "Type" / types,
    "Name" / PascalString(Byte, 'ascii'),
    "Data" / Switch(this.Type,
                    {
                        'tkInteger': typeinfo_NumCharTypes,
                        'tkChar': typeinfo_NumCharTypes,
                        'tkEnumeration': typeinfo_tkEnumeration,
                        'tkClass': typeinfo_tkClass,
                        'tkDynArray': typeinfo_tkDynArray,
                        'tkPointer': typeinfo_tkPointer,
                        'tkClassRef': typeinfo_tkClassRef,
                        'tkInterface': typeinfo_tkInterface,
                        'tkMethod': typeinfo_tkMethod,
                        'tkSet': typeinfo_tkSet,
                        'tkRecord': typeinfo_tkRecord,
                        'tkArray': typeinfo_tkArray,
                        'tkWChar': typeinfo_NumCharTypes,
                        'tkLString': typeinfo_tkLString,
                        'tkVariant': typeinfo_AttrDataOnly,
                        'tkUString': typeinfo_AttrDataOnly,
                        'tkWString': typeinfo_AttrDataOnly,
                        'tkFloat': typeinfo_tkFloat,
                        'tkInt64': typeinfo_tkInt64,
                        'tkProcedure': typeinfo_tkProcedure,
                    }, default=Error)  # Exception if unknown types are found
)

interface_entry = Struct(
    "Guid" / guid,
    "VtablePtr" / Int32ul,
    "Offset" / Int32ul,
    "GetterPtr" / Int32ul,
)

interface_table = Struct(
    "NumEntries" / Int32ul,
    "Entries" / Array(this.NumEntries, interface_entry),
)

# Used by the legacy field table, field_types_ptr points to one of these
published_field_types = Struct(
    "NumTypes" / Int16ul,
    "Types" / Array(this.NumTypes, Int32ul),
)

field_entry_legacy = Struct(
    "Offset" / Int32ul,
    "TypeIndex" / Int16ul,
    "Name" / PascalString(Byte, 'ascii'),
)

field_table_legacy = Struct(
    "FieldtypesPtr" / Int32ul,
    "Fields" / Array(this._.Header, field_entry_legacy),
)

field_entry_modern = Struct(
    "unk1" / Byte,
    "TypeinfoPtr" / Int32ul,  # PPTypeinfo
    "Offset" / Int32ul,
    "Name" / PascalString(Byte, 'ascii'),
    "NumExtra" / Int16ul,
    "Extra" / Bytes(this.NumExtra - 2),
)

field_table_modern = Struct(
    "unk2" / Bytes(4),
    "NumFields" / Int16ul,
    "Fields" / Array(this.NumFields, field_entry_modern),
)

field_table = Struct(
    # This is 0 for "new" style field tables and the number of entries for
    # "legacy" ones
    "Header" / Int16ul,
    "Modern" / If(this.Header == 0, Embedded(field_table_modern)),
    "Legacy" / If(this.Header > 0, Embedded(field_table_legacy)),
)

# Each entry points to a class vftable
fieldtypes_table = Struct(
    "NumEntries" / Int16ul,
    "Entries" / Array(this.NumEntries, Int32ul),
)

method_entry = Struct(
    # TODO: Most entries end after the name.  However some apparently
    #       have additional info, which needs to be skipped based on
    #       the size param.  Maybe add extra padding?
    "Size" / Int16ul,
    "Function_ptr" / Int32ul,
    "Name" / PascalString(Byte, 'ascii'),
)

method_table = Struct(
    "NumMethods" / Int16ul,
    "Methods" / Array(this.NumMethods, method_entry),
    # TODO: Extend this for modern Delphi
)

vftable_common = Struct(
    "vmtSelfPtr" / Int32ul,
    "vmtIntfTable" / Int32ul,
    "vmtAutoTable" / Int32ul,
    "vmtInitTable" / Int32ul,
    "vmtTypeInfo" / Int32ul,
    "vmtFieldTable" / Int32ul,
    "vmtMethodTable" / Int32ul,
    "vmtDynamicTable" / Int32ul,
    "vmtClassName" / Int32ul,
    "vmtInstanceSize" / Int32ul,
    "vmtParent" / Int32ul,
)

common_functions = Struct(
    "SafeCallException" / Int32ul,
    "AfterConstruction" / Int32ul,
    "BeforeDestruction" / Int32ul,
    "Dispatch" / Int32ul,
    "DefaultHandler" / Int32ul,
    "NewInstance" / Int32ul,
    "FreeInstance" / Int32ul,
    "Destroy" / Int32ul,
)

vftable_legacy = Struct(
    Embedded(vftable_common),
    "functions" / common_functions,
)

vftable_modern = Struct(
    Embedded(vftable_common),
    "vmtEquals" / Int32ul,
    "vmtGetHashCode" / Int32ul,
    "vmtToString" / Int32ul,
    "functions" / common_functions,
)


class PEHandler(object):

    _pe = None
    profiles = {
        "delphi_legacy": {
            "description": "Delphi (legacy)",
            "distance": 0x4C,
            "vftable_struct": vftable_legacy,
        },
        "delphi_modern": {
            "description": "Delphi (modern)",
            "distance": 0x58,
            "vftable_struct": vftable_modern,
        }
    }
    chosen_profile = None
    visited = None
    candidates = None

    def __init__(self, logger, filename=None, pe=None):
        self.logger = logger
        self._reset_queues(reset_visited=True)

        if filename:
            self._from_file(filename)

        elif pe:
            self._from_pefile(pe)

    def _reset_queues(self, reset_visited=False):
        """
        Initialise (or reset) the local work queues.  By default the queue
        of visited locations is not reset, as this should only occur once at
        startup.
        """

        if reset_visited:
            self.visited = {}

        self.candidates = {}

        # Initialise empty lists
        for table in ['typeinfo', 'fieldtable', 'methodtable']:
            if reset_visited:
                self.visited[table] = set()
            self.candidates[table] = set()

    @profile
    def _from_pefile(self, pe):
        """
        Initialise with an existing pefile object, useful when some other
        script has already created the object.
        """
        self._pe = pe
        self._mapped_data = self._pe.get_memory_mapped_image()
        self.logger.debug(
            "size of mapped data is: {}".format(len(self._mapped_data)))

        # TODO: Validate 32bit.  Need to find 64bit samples to add parsing.

        self.logger.debug(
            "ImageBase is: 0x{:08x}".format(
                self._pe.OPTIONAL_HEADER.ImageBase))

    @profile
    def _from_file(self, filename):
        """
        Initialise from a file on disk.
        """

        # TODO: Exception handling - test with junk data
        pe = pefile.PE(filename, fast_load=True)
        self._from_pefile(pe)
        self.logger.info("Loaded PE from file {}".format(filename))

    @profile
    def analyse(self):

        # TODO: Find a sample that has objects in more than one section,
        #       as this will break a number of assumptions made throughout

        sections = self._find_code_sections()
        found = False

        for s in sections:
            # Step 1 - hunt for vftables
            vftables = self._find_vftables(s)

            if vftables:
                if not found:
                    found = True
                else:
                    self.logger.warning(
                        "Have already found objects in a different section!")
                    raise Exception("Objects in more than one section")

                # Step 2 - add item references from vftables
                for offset, data in vftables.iteritems():
                    if data['vmtFieldTable']:
                        self._add_candidate(
                            data['vmtFieldTable'], 'fieldtable')

                    if data['vmtMethodTable']:
                        self._add_candidate(
                            data['vmtMethodTable'], 'methodtable')

                # Step 3 - iterate through all items repeatedly
                passes = 0
                while True:
                    found = 0
                    passes += 1

                    self.logger.info("Extracting additional data, pass {}".format(passes))

                    if passes > 16:
                        self.logger.error("Too many passes, aborting.  Please report this error")
                        break

                    # Can't update items whilst iterating, so take a local copy
                    candidates = self.candidates
                    self._reset_queues()

                    for table, data in candidates.iteritems():
                        func = getattr(self, "_parse_{}".format(table))
                        for va in sorted(data):
                            found += 1
                            self._add_visited(va, table)
                            func(s, va)

                    if found == 0:
                        break

            #self._parse_extra(s, vftables)

        if not self.chosen_profile:
            self.logger.error(
                "Didn't find any vftables.  Either this isn't Delphi, it doesn't use object orientation, or this is a bug.")
            return

        # TODO: Ensure the top class is always TObject, or warn
        # TODO: Check all parent classes have been found during the automated scan
        # TODO: Build up a hierachy of classes

    def _add_candidate(self, va, table):
        if va in self.visited[table]:
            return

        self.candidates[table].add(va)

    def _add_visited(self, va, table):
        self.visited[table].add(va)

    def _parse_typeinfo(self, section, va):
        self.logger.debug("found typeinfo at 0x{:08x}".format(va))

        start = va - section['base_va']
        section['data'].seek(start)
        table = typeinfo.parse_stream(section['data'])
        self.logger.debug(table)

        # Process references to parent or linked typeinfo structures
        for ref in ['TypeinfoPtr', 'ParentPtr']:
            if hasattr(table.Data, ref):
                ptr = getattr(table.Data, ref)

                # Some parent / typeinfo pointers appear to hold data
                # that is not actually a PPTypeInfo
                if self._in_section(section, ptr):
                    typeinfo_va = self._deref_pp(section, ptr)
                    self._add_candidate(typeinfo_va, 'typeinfo')

        if table.Type == types.tkDynArray:
            for ref in ['ElementTypePtr', 'ElementType2Ptr', 'unk5']:
                ptr = getattr(table.Data, ref)

                if self._in_section(section, ptr):
                    typeinfo_va = self._deref_pp(section, ptr)
                    self._add_candidate(typeinfo_va, 'typeinfo')
                else:
                    self.logger.debug("ptr {} to 0x{:08x} is not in this section".format(ref, ptr))


    def _deref_pp(self, section, va):
        """
        Follow a pointer and TODO
        """
        ptr_offset = self._va_to_offset(section, va)
        section['data'].seek(ptr_offset)
        (value,) = self._unpack_stream("I", section['data'])
        return value

    def _va_to_offset(self, section, va):
        return va - section['base_va']

    def _parse_methodtable(self, section, va):

        self.logger.debug(
            "found *method table at 0x{:08x}".format(va))

        start = self._va_to_offset(section, va)
        section['data'].seek(start)
        table = method_table.parse_stream(section['data'])

        self.logger.debug(table)

    def _parse_fieldtable(self, section, va):
        """

        """
        # TODO: This function should return a generic Fields object

        self.logger.debug(
            "found field table at 0x{:08x}".format(va))

        # TODO: Make a convenience function for va to offset
        start = va - section['base_va']
        section['data'].seek(start)
        table = field_table.parse_stream(section['data'])
        self.logger.debug(table)

        # For legacy field tables, parse the fieldtypes table and
        # extract all references to Typeinfo structures.
        if table.Legacy:
            self.logger.debug(table.Legacy.FieldtypesPtr)

            # TODO: Refactor using _deref_pp
            types_offset = table.Legacy.FieldtypesPtr - section['base_va']
            section['data'].seek(types_offset)
            types_table = fieldtypes_table.parse_stream(section['data'])

            self.logger.debug("types table:")
            self.logger.debug(types_table)
            for entry in types_table.Entries:
                pass

        elif table.Modern:
            # This is a pointer to a pointer, need to follow
            for field in table.Modern.Fields:

                if self._in_section(section, field.TypeinfoPtr):
                    # TODO: Refactor using _deref_pp and _va_to_offset
                    typeinfo_ptr_offset = field.TypeinfoPtr - \
                        section['base_va']
                    section['data'].seek(typeinfo_ptr_offset)
                    (typeinfo_va,) = self._unpack_stream("I", section['data'])

                    self._add_candidate(typeinfo_va, 'typeinfo')
#                    typeinfo_offset -= typeinfo_va - section['base_va']

    @profile
    def _find_code_sections(self):
        """
        Iterate over all code sections in a PE file and return a dictionary
        including section data.
        """
        sections = []

        # Check each code segment to see if it has the code flag
        for section in self._pe.sections:
            if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:

                # pefile doesn't remove the null padding, trim any whitespace
                # TODO: Consider whether removing non-printable would be better
                name = section.Name
                name = name.rstrip(" \r\n\0")

                raw_offset = section.PointerToRawData
                size = section.SizeOfRawData
                base = section.VirtualAddress

                base_va = self._pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                data = io.BytesIO(self._mapped_data[base:base + size])

                self.logger.debug(
                    "Found section {}, raw offset 0x{:08x}, size: 0x{:08x}, base VA: 0x{:08x}".format(
                        name, raw_offset, size, base_va))

                sections.append({'name': name,
                                 'base': base,
                                 'data': data,
                                 'raw_offset': section.PointerToRawData,
                                 'size': size,
                                 'base_va': base_va})

        return sections

    # TODO: Move to util class

    def _extract_pascal_string(self, stream, offset):
        stream.seek(offset)
        (length,) = self._unpack_stream('B', stream)
        stream.seek(offset)
        (text,) = self._unpack_stream("{}p".format(length + 1), stream)
        return text

    # TODO: Move to util class

    def _in_section(self, section, va):
        """
        Validate that a virtual address exists within a section.
        """
        if not va:
            return False

        if va < section['base_va'] or va > section['base_va'] + \
                section['size']:
            return False

        return True

    # TODO: Move to util class
    @staticmethod
    def _unpack_stream(fmt, stream):
        """
        Unpack data from a streaming object, e.g. BytesIO().
        """
        size = struct.calcsize(fmt)
        buf = stream.read(size)
        return struct.unpack(fmt, buf)

    def _parse_extra(self, section, vftables):

        for va, v in vftables.iteritems():


            start = v['vmtIntfTable']
            if start:
                self.logger.debug("found intftable at 0x{:08x}".format(start))

                start -= section['base_va']
                blah = interface_table.parse(section['mmap'][start:])

                # TODO: Refactor
                for e in blah.entries:
                    guid = e.guid
                    fields = [
                        guid.Data1,
                        guid.Data2,
                        guid.Data3,
                        guid.Data4,
                        guid.Data5]
                    human_guid = "-".join([hexlify(d) for d in fields])
                    #self.logger.debug("*GUID: {}".format(human_guid))

                # self.logger.debug(blah)

    def _validate_vftable(self, section, offset, structure):
        """
        Validate and extract a vftable from a specific offset.
        """

        section['data'].seek(offset)
        data = structure.parse_stream(section['data'])
        # self.logger.debug(data)

        # A number of checks to ensure our brute force method has found a valid
        # vftable.  Note that legitimate code produced by the Delphi compiler
        # will often include unrelated sequences of bytes which aren't vftables
        # but pass basic checks.  Therefore this should be robust enough to
        # reject them.

        # Validate that all pointers are within the code section.  This
        # removes a lot of incorrect detections from the brute force search.
        #
        # Instance size is not a pointer, self pointer has already been
        # validated.
        ignore = ["vmtInstanceSize", "vmtSelfPtr"]

        for name, value in data.iteritems():
            if name.startswith("vmt") and name not in ignore:
                if value and not self._in_section(section, value):
                    return None

        # Check the instantiated size is not more than 500Kib
        if data['vmtInstanceSize'] > 1024 * 500:
            self.logger.debug("Improbably large vmtInstanceSize")
            return None

        # Extract the class name
        name_offset = data['vmtClassName'] - section['base_va']
        name = self._extract_pascal_string(section['data'], name_offset)
        #self.logger.debug("Name: {}".format(name))

        # TODO: Parse additional class functions
        # TODO: Turn into a vftable object

        return data

    def _find_vftables(self, section):
        """
        """

        matches = {}
        vftables = {}

        # TODO: This is incompatible with the user providing a default profile
        for name, profile in self.profiles.iteritems():
            i = 0
            candidates = 0

            while i < section['size'] - profile['distance']:
                fail = False
                section['data'].seek(i)
                (ptr,) = self._unpack_stream('I', section['data'])

                # Calculate the virtual address of this location
                va = section['base_va'] + i

                if (va + profile['distance']) == ptr:
                    #self.logger.debug("Found a potential vftable at 0x{:08x}".format(va))

                    tmp = self._validate_vftable(
                        section, i, profile['vftable_struct'])
                    if tmp:
                        vftables[va] = tmp
                        candidates += 1

                # TODO: 64bit incompatibility
                i += 4

            matches[name] = candidates

        # TODO: This is incompatible with the user providing a default profile
        for name, candidates in matches.iteritems():
            if candidates > 0:
                if self.chosen_profile:
                    self.logger.error(
                        "Found more than one matching profile.  Please specify one on the commandline to continue.")
                    self.logger.error(profiles)
                    sys.exit(1)
                else:
                    self.chosen_profile = self.profiles[name]

        if self.chosen_profile:
            self.logger.info("Found {} vftables in section {} using profile {}".format(
                len(vftables), section['name'], self.chosen_profile['description']))

        # TODO: If we don't find a profile, scan the section manually
        #       for any presence of \x07TOBJECT.

        # TODO: Consider updating a section specific vftable dict here, rather
        # than returning?
        return vftables


class DelphiParser(object):

    handler = None
    logger = None

    def __init__(self, filename=None, pe=None, logger=None, debug=0):
        self._init_logging(logger, debug)

        # TODO: Sanity check the input filename or PE file.

        if filename:
            # TODO: Auto detect input file type and use the right handler
            self.handler = PEHandler(logger=self.logger, filename=filename)

        elif pe:
            self.handler = PEHandler(logger=self.logger, pe=pe)

        else:
            raise AttributeError("Need either filename or pe argument")

        self.handler.analyse()

    def _init_logging(self, logger, debug):
        """
        Initialise logging.  If the caller has setup logging the existing
        object is used directly.  Otherwise a default logger is created.
        """
        if logger:
            self.logger = logger
        else:
            logging.basicConfig(level=logging.ERROR)
            self.logger = logging.getLogger('pythia')

            if debug == 1:
                self.logger.setLevel(logging.INFO)
            elif debug > 1:
                self.logger.setLevel(logging.DEBUG)


def load_config():
    """ Load our data file containing Delphi information """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, "config.yaml")

    # TODO: Error handling here if the file can't be read
    with open(config_file, "r") as fh:
        config = yaml.load(fh)
        return _merge_config(config)


def _merge_config(config):
    """ Merge the base profile with all others """
    base = config['profiles']['base']

    # Copy each profile over the base profile, ensuring changes
    # values are updated.
    for k, p in config['profiles'].iteritems():
        if k == "base":
            continue

        merged = base.copy()
        merged.update(p)
        config['profiles'][k] = merged

    return config


def make_a_tree(classes):
    t = Tree()
    iteration = 0
    seen = set()

    # We can't guarantee classes will appear in order of inheritance.  Therefore
    # loop through until all classes are in the tree OR we hit a bug (e.g. a
    # parent is missing for some reason).
    while True:
        added = 0

        for va, c in classes.iteritems():
            if va in seen:
                continue

            parent_location = c['structure']['vmtParent']['value']
            if parent_location:
                # Try adding those node with a link to the parent.  This may
                # fail if the parent hasn't been seen, in which case silently
                # skip and move to the next.  It will be added in a future
                # pass.
                try:
                    t.create_node(
                        "{} (at 0x{:08x})".format(
                            c['name'],
                            c['va']),
                        c['va'],
                        parent_location)
                    seen.add(c['va'])
                    added += 1
                except treelib.tree.NodeIDAbsentError:
                    pass
            else:
                t.create_node(
                    "{} (at 0x{:08x})".format(
                        c['name'], c['va']), c['va'])
                seen.add(c['va'])
                added += 1

        iteration += 1
        print("[i] Added {} nodes to tree, iteration {}, seen {} / {}".format(added,
                                                                              iteration, len(seen), len(classes)))

        # Break if we've seen all classes OR we didn't add one
        # to the tree this time through.
        if not added or len(seen) == len(classes):
            break

        if iteration > 16:
            print("[!] Reached 16 levels of inheritance, stopping")
            break

    if len(seen) < len(classes):
        print("[!] Warning: some classes could not be added to the tree, likely bug")

    # Add an option to dump this to an output file
    t.show(line_type="ascii")

    # Walk the tree and pull out class information
    for node in t.expand_tree(mode=Tree.DEPTH):
        c = classes[node]
        p = None

        # Get the parent class
        if c['structure']['vmtParent']['value']:
            p = classes[c['structure']['vmtParent']['value']]

        # Walk the vtable structure (interface table, method table etc.) and
        # check which were inherited directly from the parent class.
        for item, data in c['structure'].iteritems():
            if p and p['structure'][item]['value'] == data['value']:
                data['inherited'] = True
            else:
                data['inherited'] = False

        for offset, f in c['functions'].iteritems():
            # Check whether this function was inherited from the parent (they
            # point to the same place) or if it was overridden.  Modify the
            # input in place (using a class would be more appropriate).
            f['inherited'] = False
            name = "{}_{}".format(c['name'], f['name'])

            try:
                if p:
                    parent_fn = p['functions'][offset]
                    if f['location'] == parent_fn['location']:
                        f['inherited'] = True
                        name = "{}_{}".format(p['name'], f['name'])

            except KeyError:
                pass

            f['name'] = name

    # TODO: Return the tree, as it's useful for other activities


# TODO: Split out into a class and then a commandline wrapper

def main():
    # TODO: Move into class
    #config = load_config()

    # TODO: Argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--profile",
        type=str,
        help="set the version of Delphi (default: auto)",
        default="auto")
    parser.add_argument(
        "-v",
        "--verbose",
        help="print more messages, use twice for maximum verbosity",
        default=0,
        action="count")
    parser.add_argument("file", help="portable executable file to process")
    args = parser.parse_args()

    engine = DelphiParser(filename=args.file, debug=args.verbose)
    sys.exit(0)

    # TODO: Add Delphi version etc.
    # TODO: Move into
    info = {"creator": "pythia, a python tool to parse information from Delphi executables",
            "version": 1,
            "profile": args.profile,
            "image_base": pe.OPTIONAL_HEADER.ImageBase}

    output = {"info": info, "classes": classes}

    # TODO: Wrap the output with some data about the input file
    with open("output.json", "w") as fh:
        fh.write(json.dumps(output))


if __name__ == "__main__":
    main()
