from __future__ import print_function
import idaapi
import json

with open("output.json", "r") as fh:
    data = json.load(fh)

for item in data["items"]:
    print(item)
    MakeComm(item['va'], item['name'].encode("ascii"))

    if item["type"] == "p":
        MakeUnknown(item["va"], item["size"], DOUNK_SIMPLE)
        #res = MakeStr(item["va"], item["va"] + item["size"])
        idaapi.make_ascii_string(item["va"], item["size"], ASCSTR_PASCAL)
        #print("pascal {}".format(res))
    
    elif item["type"] == "I":
        MakeUnknown(item["va"], item["size"], DOUNK_SIMPLE)
        MakeDword(item["va"])

    elif item["type"] == "H":
        MakeUnknown(item["va"], item["size"], DOUNK_SIMPLE)
        MakeWord(item["va"])

    elif item["type"] == "G":
        MakeUnknown(item["va"], item["size"], DOUNK_SIMPLE)
        MakeDword(item["va"])
        MakeWord(item["va"] + 4)
        MakeWord(item["va"] + 6)
        MakeWord(item["va"] + 8)
        MakeData(item["va"] + 10, FF_BYTE, 6, 0)

        comm = "GUID: {}".format(item["data"])
        MakeComm(item['va'], comm)
        

#idaapi.refresh_strlist(0, 1)
