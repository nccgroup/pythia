import logging
from binascii import unhexlify
from .windows import PEHandler
from .objects import Vftable


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
            self.handler = PEHandler(
                logger=self.logger, context=self.program, filename=filename
            )

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

    # These may be set as parsing progresses.  Depending on what data is passed, some
    # of these will remain unset.  For example, license and unit information will not
    # be available if a single code section is parsed.
    license = None
    units = None
    header_length = None
    items = {}
    name_hints = []

    # A list of pythia.core.objects.Section objects
    code_sections = []
    data_sections = []
    # Which section contains vftables (e.g. where are the Delphi objects)
    object_section = None

    # Will be a VersionHelper instance
    version = None

    def has_section(self, name):
        section = self.get_section(name)

        if section is not None:
            return True

        return False

    def get_section(self, name):
        if name is None:
            raise AttributeError("Need a section name")

        for s in self.code_sections:
            if s.name == name:
                return s

        for s in self.data_sections:
            if s.name == name:
                return s

        return None

    def add_name_hint(self, va, name):
        # TODO: Ensure these are unique
        self.name_hints.append({"va": va, "name": name})

    def add_item(self, va, obj):

        # TODO: Check there is not an object here already
        self.items[va] = obj

    def get_item(self, va):
        try:
            return self.items[va]
        except KeyError:
            return None

    def iter_items(self, obj_type=None):
        for va, obj in self.items.items():
            if not obj_type:
                yield obj
            elif type(obj) == obj_type:
                yield obj

    def get_class(self, name):
        for obj in self.iter_items(obj_type=Vftable):
            if obj.name == name:
                return obj

        return None

    # TODO: Add version so that parsers know which Delphi to target
