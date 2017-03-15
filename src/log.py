"""Logging Module"""
#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:
from __future__ import absolute_import

import logging
import sys

from .utils import report, LOG_LE_AGENT, EXIT_ERR

class Log(object):
    """Log object"""
    def __init__(self):
        self.log = logging.getLogger(LOG_LE_AGENT)
        if not self.log:
            report("Cannot open log output")
            sys.exit(EXIT_ERR)

        self.log.setLevel(logging.INFO)

        self.stream_handler = logging.StreamHandler()
        self.stream_handler.setLevel(logging.DEBUG)
        self.stream_handler.setFormatter(logging.Formatter("%(message)s"))
        self.log.addHandler(self.stream_handler)


    def enable_daemon_mode(self):
        """Enable daemon mode for log object"""
        self.log.removeHandler(self.stream_handler)
        shandler = logging.StreamHandler()
        shandler.setLevel(logging.DEBUG)
        shandler.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
        self.log.addHandler(shandler)


log = Log()#pylint: disable=invalid-name
