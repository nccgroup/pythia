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

VERSION_MAJOR = 0
VERSION_MINOR = 0
VERSION_PATCH = 1
VERSION_STRING = ".".join(str(i) for i in [VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH])
