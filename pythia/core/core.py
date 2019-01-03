import logging
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

