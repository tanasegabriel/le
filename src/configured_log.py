"""Configured Log Module"""

class ConfiguredLog(object):

    """Configured Log Class"""

    def __init__(self, name, token, destination, path, formatter, entry_identifier):
        self.name = name
        self.token = token
        self.destination = destination
        self.path = path
        self.formatter = formatter
        self.entry_identifier = entry_identifier
        self.logset = None
        self.logset_id = None
        self.log_id = None
