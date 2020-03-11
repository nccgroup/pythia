from __future__ import print_function
import json
import idaapi


print("[+] Loading RTTI information from JSON file")

with open("output.json", "r") as fh:
    data = json.load(fh)

print("[+] Finished loading, starting to rename")

for item in data["items"]:
    ida_bytes.del_items(item["va"], ida_bytes.DELIT_SIMPLE, item["size"])
    idc.set_cmt(item['va'], item['name'], 0)

    # A short Pascal string (1 byte length, ASCII data, no null terminator).
    # Note it seems these can be UTF in modern Delphi, e.g. object names.
    if item["type"] == "p":
        ret = ida_bytes.create_strlit(item["va"], item["size"], ida_nalt.STRTYPE_PASCAL)
    
    # 4 byte integer value
    elif item["type"] == "I":
        ida_bytes.create_data(item["va"], FF_DWORD, 4, ida_idaapi.BADADDR)

    # 2 byte integer value
    elif item["type"] == "H":
        ida_bytes.create_data(item["va"], FF_WORD, 2, ida_idaapi.BADADDR)

    # 1 byte value, either integer or a single byte
    elif item["type"] == "B":
        ida_bytes.create_data(item["va"], FF_BYTE, 1, ida_idaapi.BADADDR)

    # GUID, custom format
    elif item["type"] == "G":
        ida_bytes.create_data(item["va"], FF_DWORD, 4, ida_idaapi.BADADDR)
        ida_bytes.create_data(item["va"] + 4, FF_WORD, 2, ida_idaapi.BADADDR)
        ida_bytes.create_data(item["va"] + 6, FF_WORD, 2, ida_idaapi.BADADDR)
        ida_bytes.create_data(item["va"] + 8, FF_WORD, 2, ida_idaapi.BADADDR)
        ida_bytes.create_data(item["va"] + 10, FF_BYTE, 6, ida_idaapi.BADADDR)
        	
        comm = "GUID: {}".format(item["data"])
        idc.set_cmt(item['va'], comm, 0)

seen = set()
for item in data["name_hints"]:
    if item["va"] in seen:
        #print("Already renamed 0x{:08x}".format(item["va"]))
        comm = idc.get_cmt(item["va"], 0)
        if comm:
            comm += "\n{}".format(item["name"])
        else:
            comm = item["name"]
        idc.set_cmt(item["va"], str(comm), 0)
        continue
        
    idc.set_name(item["va"], str(item["name"]), SN_NOWARN)
    seen.add(item["va"])

print("[+] Finished renaming, rebuilding IDA's string list")
ida_strlist.build_strlist()
print("[+] Done!")
