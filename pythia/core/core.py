import logging
from binascii import unhexlify
from .windows import PEHandler


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
            self.logger = logging.getLogger("pythia")

            if debug == 1:
                self.logger.setLevel(logging.INFO)
            elif debug > 1:
                self.logger.setLevel(logging.DEBUG)


class DelphiProgram(object):

    license = None
    units = None
    classes = None


class License(object):
    """
    Represents a Delphi license, and can convert raw DVCLAL data to Delphi
    version information.
    """

    license_type = None

    _known_licenses = {
        "Standard": unhexlify("23785D23B6A5F31943F3400226D111C7"),
        "Professional": unhexlify("A28CDF987B3C3A7926713F090F2A2517"),
        "Enterprise": unhexlify("263D4F38C28237B8F3244203179B3A83"),
    }

    def __init__(self, raw_data=None):
        self.logger = logging.getLogger("pythia.{}".format(self.__class__.__name__))

        if raw_data:
            self._from_bytes(raw_data)

    def _from_bytes(self, data):
        """
        Convert a stream of bytes to a license version (Standard, Professional
        or Enterprise) or None if the license is not recognised.
        """

        for version, raw in self._known_licenses.items():
            if raw == data:
                self.license_type = version
                return

        # TODO: Support "fake" Delphi licenses, where the author has calculated
        #       custom values.  Find some test samples to use.  See:
        #       https://stackoverflow.com/questions/18720045/what-are-the-list-of-all-possible-values-for-dvclal
        raise AttributeError("Did not recognise raw data as a valid license")


class DelphiClass(object):
    pass


class DelphiUnit(object):
    pass
