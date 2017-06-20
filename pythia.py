# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

from __future__ import print_function
from struct import *
from treelib import Node, Tree
import pefile
import sys
import os
import treelib
import yaml

########       _   _     _
#  _ __  _   _| |_| |__ (_) __ _
# | '_ \| | | | __| '_ \| |/ _` |
# | |_) | |_| | |_| | | | | (_| |
# | .__/ \__, |\__|_| |_|_|\__,_|
# |_|    |___/
#
# Extract Delphi class information from PE files.  See Readme.md.
#
# Author: David Cannings (@edeca)
#   Date: January 2017
########

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
    for k,p in config['profiles'].iteritems():
        if k == "base":
            continue

        merged = base.copy()
        merged.update(p)
        config['profiles'][k] = merged

    return config


def get_code_segments(pe):
    """ Get a dict containing all code segments with their data """
    segments = []

    # Check each code segment to see if it has the code flag
    for section in pe.sections:
        if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:

            # pefile doesn't remove the null padding, trim
            name = section.Name
            length = section.Name.find("\x00")
            if length > 0:
                name = section.Name[:length]

            print("[*] Found a code section named {}".format(name))

            # mmap the data
            code = pe.get_memory_mapped_image()[section.PointerToRawData:section.PointerToRawData+section.SizeOfRawData]
            base = section.VirtualAddress
            segments.append({ 'name': name, 'base': base, 'mmap': code, 'raw_data': section.PointerToRawData })
    
    return segments


def validate_vftable(data, base, va, offset, profile):
    """ Check whether a vftable candidate is legitimate """

    class_functions = {}
    info = {}
    info['va'] = va
    info['start_va'] = offset - profile['distance']

    # TODO: Bounds checking
    # TODO: Map the whole structure into something we can access more easily

    # A number of checks to ensure our brute force method has found a valid
    # vftable.  Note that legitimate code produced by the Delphi compiler
    # will often include unrelated sequences of bytes which aren't vftables
    # but pass basic checks.  Therefore this should be robust enough to
    # reject them.

    # Validate vmtSelfPtr points to start (note this is done already
    # given the current search method, but an improved mechanism may
    # not have checked).

    # Loop through known offsets and extract the pointer values
    info['pointers'] = {}
    for pos,name in profile['offsets'].iteritems():
        (ptr,) = unpack_from('I', data,  offset + pos)
        
        info['pointers'][name] = ptr

        # TODO: Check it's within a code segment, or null

    # Validate vmtInstanceSize is sensible.  This is the size of
    # an initialised instance of the class (used to allocate memory).
    # TODO: Ensure this is a sensible value, 0.5MiB chosen
    if info['pointers']['vmtInstanceSize'] > 512 * 1024:
        print("[D] Improbably large vmtInstanceSize 0x{:08x}, skipping".format(info['pointers']['vmtInstanceSize']))
        return None

    # Validate the vmtName points to a Pascal string within this section
    name_ptr = info['pointers']['vmtClassName'] - base
    if name_ptr < 0 or name_ptr > len(data):
        print("[!] Name pointer is outside this section?")
        return

    # TODO: Validate the vmtName points to a Pascal string    
    # Dereference and obtain length from first byte
    (name,) = unpack_from('255p', data, name_ptr)
    print("[i] Found class: {}".format(name))
    info['name'] = name

    # TODO: Check each character is ASCII (no Unicode support in short string)

    info['functions'] = {}

    # Parse the standard functions
    for pos, n in profile['functions'].iteritems():
        (ptr,) = unpack_from('I', data, offset + pos)

        # TODO: Validate VA is within a code section
        info['functions'][pos] = { 'offset': pos, 'name': n, 'va': ptr }

    # Parse user functions (including those which are inherited) 
    # TODO: We also need to ignore all the other tables (type / method / interface etc.) 
    #       in addition to the name pointer.  Essentially find the earliest offset after
    #       the start of the vftable.
    for pos in range(0, name_ptr - offset, 4):
        (ptr,) = unpack_from('I', data, offset + pos)

        # Break as soon as we find one which isn't valid
        # TODO: Instead check it's within a code section, this check is not particularly 
        #       robus
        rva = ptr - base
        if rva < 0 or rva > len(data):
            break

        info['functions'][pos] = { 'offset': pos, 'name': 'function_{:04x}'.format(pos), 'va': ptr }

    # Ensure the topmost class is always TObject, therefore all classes
    # inherit from it eventually.
    # This may be an incorrect assumption, testing required
    if info['pointers']['vmtParent'] == 0 and name != "TObject":
        print("[!] No parent but this is not TObject?  Probable bug!")
        return None

    # TODO: Should be wrapping all this up in a class somehow
    return info


def make_a_tree():
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

            if c['pointers']['vmtParent']:
                try:
                    t.create_node("{} (at 0x{:08x})".format(c['name'], c['va']), c['va'], c['pointers']['vmtParent'])
                    seen.add(c['va'])
                    added += 1
                except treelib.tree.NodeIDAbsentError:
                    pass
            else:
                t.create_node("{} (at 0x{:08x})".format(c['name'], c['va']), c['va'])
                seen.add(c['va'])
                added += 1 
        
        iteration += 1
        print("[i] Added {} nodes to tree, iteration {}, seen {} / {}".format(added, iteration, len(seen), len(classes)))

        # Break if we've seen all classes OR we didn't add one
        # to the tree this time through.
        if not added or len(seen) == len(classes):
            break

    if len(seen) < len(classes):
        print("[!] Warning: some classes could not be added to the tree, likely bad parent relationships")

    # Add an option to dump this to an output file
    #t.show(line_type="ascii")

    # Walk the tree and pull out class informationA
    for node in t.expand_tree(mode=Tree.DEPTH):
        c = classes[node]
        p = None
        if c['pointers']['vmtParent']:
            p = classes[c['pointers']['vmtParent']]

        for offset, f in c['functions'].iteritems():
            # Check whether this function was inherited from the parent (they
            # point to the same place) or if it was overridden.
            f['inherited'] = False
            name = "{}_{}".format(c['name'], f['name'])

            try:
                if p:
                    parent_fn = p['functions'][offset]
                    if f['va'] == parent_fn['va']:
                        f['inherited'] = True
                        name = "{}_{}".format(p['name'], f['name'])

            except KeyError:
                pass

            f['name'] = name


def main():
    config = load_config()

    # Load the PE
    pe = pefile.PE(sys.argv[1])
    print("[i] ImageBase is: {:08x}".format(pe.OPTIONAL_HEADER.ImageBase))

    classes = {}
    names = set()

    # TODO: Take a --profile option pointing at the right one
    profile = config["profiles"]["delphi2xxx"]

    for s in get_code_segments(pe):
        code = s['mmap']
        base = s['base'] + pe.OPTIONAL_HEADER.ImageBase
        #print("[i] Parsing section {} (length {})".format(s['name'], len(code)))

        # Skip through 4 bytes at a time.  It seems that the Delphi compiler
        # inserts padding to align on a boundary, so this is a valid method.
        i = 0
        while i < len(code) - 4:
            (offset,) = unpack_from('I', code, i)

            va = i + s['raw_data'] + pe.OPTIONAL_HEADER.ImageBase

            if (va + profile['distance']) == offset:
                print("[i] Found a candidate at {:08x} (section offset {:08x}), data is {:08x}".format(va, i, offset))
                # TODO: Work out how to calculate this repeatably
                fudge_factor = pe.OPTIONAL_HEADER.ImageBase + s['raw_data']
                info = validate_vftable(code, fudge_factor, va, i + profile['distance'], profile)

                if info:
                    if info['name'] in names:
                        print("[?] Warning: duplicate class found: {}".format(info['name']))
                    else:
                        names.add(info['name'])

                    classes[va] = info

            i += 4

if __name__ == "__main__":
    main()
