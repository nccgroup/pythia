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

idaapi.refresh_strlist(0, 0)