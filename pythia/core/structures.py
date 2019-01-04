# vim: autoindent expandtab tabstop=4 shiftwidth=4 softtabstop=4
# filetype=python

"""
This file holds all of the structures which map to Delphi types.
"""

from construct import *

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

package_name = Struct(
    "HashCode" / Int8ul,
    "Name" / CString("ascii"),
)

unit_name = Struct(
    "Flags" / Int8ul,
    "HashCode" / Int8ul,
    "Name" / CString("ascii"),
)

packageinfo = Struct(
    "Flags" / Int32ul,
    "RequiresCount" / Int32ul,
    "Requires" / Array(this.RequiresCount, package_name),
    "ContainsCount" / Int32ul,
    "Contains" / Array(this.ContainsCount, unit_name),
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