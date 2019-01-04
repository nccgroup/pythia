"""
Various helpers to provide utility functions which can also be used from other code.
"""
import logging
from binascii import unhexlify
from .structures import packageinfo

class LicenseHelper(object):
    """
    Utility class to convert raw DVCLAL data to Delphi version information.
    """

    # TODO: Support "fake" Delphi licenses, where the author has calculated
    #       custom values.  Find some test samples to use.  See:
    #       https://stackoverflow.com/questions/18720045/what-are-the-list-of-all-possible-values-for-dvclal

    known_licenses = {
        "Standard": unhexlify("23785D23B6A5F31943F3400226D111C7"),
        "Professional": unhexlify("A28CDF987B3C3A7926713F090F2A2517"),
        "Enterprise": unhexlify("263D4F38C28237B8F3244203179B3A83"),
    }

    def from_bytes(self, data):
        """
        Convert a stream of bytes to a license version (Standard, Professional
        or Enterprise) or None if the license is not recognised.
        """

        for version, raw in self.known_licenses.items():
            if raw == data:
                return version

        return None


class PackageInfoHelper(object):
    """
    Utility class to parse PACKAGEINFO data to a list of required & contained
    units.
    """
    def __init__(self):
        # TODO: Move to a static function that can be called from anywhere
        self.logger = logging.getLogger("pythia.{}".format(self.__class__.__name__))


    # TODO: This should return a collection of objects, e.g. PackageInfo for both
    #       required and contained units.
    def from_bytes(self, data):
        """
        Convert a stream of bytes to a dictionary representation of the
        structure.
        """

        # Docs for TPackageInfoHeader at:
        # https://github.com/Fr0sT-Brutal/Delphi_MiniRTL/blob/master/SysUtils.pas#L20087
        info = packageinfo.parse(data)
        self.logger.debug(info)
