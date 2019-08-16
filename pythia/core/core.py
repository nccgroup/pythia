import logging
from binascii import unhexlify
from .windows import PEHandler


class DelphiParser(object):

    handler = None

    def __init__(self, filename=None, pe=None, logger=None, debug=0):
        self._init_logging(logger, debug)

        # TODO: Sanity check the input filename or PE file & exception handling
        #       for pefile

        # TODO: Take a data buffer (or pefile) and mode, e.g.:
        #       -> pefile
        #       -> raw file
        #       -> raw section (user provides base VA etc.)

        self.program = DelphiProgram()

        if filename:
            # TODO: Auto detect input file type and use the right handler
            self.handler = PEHandler(logger=self.logger, context=self.program, filename=filename)

        elif pe:
            self.handler = PEHandler(logger=self.logger, context=self.program, pe=pe)

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
    items = []
    name_hints = []

    # A list of pythia.core.objects.Section objects
    code_sections = []
    data_sections = []

    # TODO: Add version so that parsers know which Delphi to target


class DelphiClass(object):
    pass


class DelphiUnit(object):
    pass

