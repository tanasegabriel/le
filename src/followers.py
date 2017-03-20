"""Follower Module"""
#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:

#pylint: disable=too-many-instance-attributes
from __future__ import absolute_import

import glob
import os
import sys
import threading
import time

from logentries.constants import REOPEN_INT, REOPEN_TRY_INTERVAL, \
    FILE_END, FILE_BEGIN, MAX_BLOCK_SIZE, TAIL_RECHECK, \
    LINE_SEPARATOR, NAME_CHECK, FOLLOWER_JOIN_INTERVAL, \
    RETRY_GLOB_INTERVAL, MAX_FILES_FOLLOWED, FOLLOWMULTI_JOIN_INTERVAL
from logentries.log import log


class Follower(object):

    """
    The follower keeps an eye on the file specified and sends new events to the
    logentries infrastructure.  """

    def __init__(self,
                 name,
                 entry_filter,
                 entry_formatter,
                 transport,
                 state,
                 config,
                 disable_glob=False):
        """ Initializes the follower. """
        self.name = name
        self.real_name = None
        self.entry_filter = entry_filter
        self.entry_formatter = entry_formatter
        self.transport = transport
        self.config = config
        # FollowMultilog usage
        self._disable_glob = disable_glob

        self._load_state(state)
        self._file = None
        self._shutdown = False
        self._read_file_rest = ''
        self._entry_rest = []
        self._worker = threading.Thread(target=self.monitorlogs, name=self.name)
        self._worker.daemon = True
        self._worker.start()
        self._state = None


    def get_state(self):
        """Get State"""
        return self._state


    def get_name(self):
        """Get name"""
        return self.name


    def _load_state(self, state):
        """Load state and set to default if not set"""
        if state:
            self._update_state(state['filename'], state['position'])
        else:
            # -1 here means we'll seek to the end of the first file
            self._update_state(None, -1)


    def _update_state(self, real_name, file_position):
        """Update state with name and position"""
        self._state = {
            'filename': real_name,
            'position': file_position,
        }


    def _file_candidate(self):
        """
        Returns list of file names which corresponds to the specified template.
        """
        try:
            candidates = glob.glob(self.name)

            if len(candidates) == 0:
                return None

            candidate_times = [[os.path.getmtime(name), name]
                               for name in candidates]
            candidate_times.sort()
            candidate_times.reverse()
            return candidate_times[0][1]
        except os.error:
            return None


    def _open_log(self, filename=None, position=0):
        """Keeps trying to re-open the log file. Returns when the file has been
        opened or when requested to remove.

        filename, if specified, is name of a file that is being open on first attempt
        position indicates the desired initial position, -1 means end of file
        """
        error_info = True
        self.real_name = None
        first_try = True

        while not self._shutdown:
            # FollowMultilog usage
            if self._disable_glob:
                candidate = self.name
            else:
                if first_try and filename:
                    candidate = filename
                else:
                    candidate = self._file_candidate()

            if candidate:
                self.real_name = candidate
                try:
                    self._close_log()
                    self._file = open(self.real_name)
                    new_position = 0
                    if first_try:
                        if position == -1:
                            self._set_file_position(0, FILE_END)
                            new_position = self._get_file_position()
                        elif position != 0:
                            self._set_file_position(position)
                            new_position = position
                    self._update_state(self.real_name, new_position)
                    break
                except IOError:
                    pass

            if error_info:
                log.log.info("Cannot open file '%s', re-trying in %ss intervals",
                             self.name, REOPEN_INT)
                error_info = False
            first_try = False
            time.sleep(REOPEN_TRY_INTERVAL)


    def _close_log(self):
        if self._file:
            try:
                self._file.close()
            except IOError:
                pass
            self._file = None


    def _log_rename(self):
        """Detects file rename."""

        # Get file candidates
        candidate = self._file_candidate()
        if not candidate:
            return False

        try:
            ctime1 = os.fstat(self._file.fileno()).st_mtime
            ctime_new = os.path.getmtime(candidate)
            ctime2 = os.fstat(self._file.fileno()).st_mtime

            if ctime1 == ctime2 and ctime1 != ctime_new:
                # We have a name change according to the time
                return True
            return False
        except os.error:
            pass


    def _read_log_lines(self):
        """ Reads a block of lines from the log. Checks maximal line size. """
        size_hint = MAX_BLOCK_SIZE - len(self._read_file_rest)
        buff = self._file.read(size_hint)
        buff_lines = buff.split('\n')
        if len(self._read_file_rest) > 0:
            buff_lines[0] = self._read_file_rest + buff_lines[0]

        self._read_file_rest = buff_lines[-1]

        # Limit size of _read_file_rest
        if len(self._read_file_rest) >= MAX_BLOCK_SIZE:
            buff_lines.append(self._read_file_rest[:MAX_BLOCK_SIZE])
            self._read_file_rest = self._read_file_rest[MAX_BLOCK_SIZE:]

        return [line for line in buff_lines[:-1]]


    def _set_file_position(self, offset, start=FILE_BEGIN):
        """ Move the position of filepointers."""
        self._file.seek(offset, start)


    def _get_file_position(self):
        """ Returns the position filepointers."""
        pos = self._file.tell()
        return pos


    def _collect_lines(self, lines):
        """Accepts lines received and merges them to multiline events.
        """
        # Fast track
        if not lines:
            if self._entry_rest:
                events = [LINE_SEPARATOR.join(self._entry_rest)]
                self._entry_rest = []
            else:
                events = []
            return events
        # Entry separator is specified
        new_lines = []
        new_entry = self._entry_rest
        self._entry_rest = []
        for line in lines:
            if new_entry:
                new_lines.append(LINE_SEPARATOR.join(new_entry))
                new_entry = []
            new_entry.append(line)
        self._entry_rest = new_entry
        return new_lines


    def _get_lines(self):
        """Returns a block of newly detected line from the log. Returns None in
        case of timeout.
        """

        # TODO: investigate select-like approach?
        idle_cnt = 0
        lines = []
        while not self._shutdown:
            # Collect lines
            lines = self._read_log_lines()
            lines = self._collect_lines(lines)
            if lines:
                break

            # No line, wait
            time.sleep(TAIL_RECHECK)

            lines = self._collect_lines([])
            if lines:
                break

            # Log rename check
            idle_cnt += 1
            if idle_cnt == NAME_CHECK:
                if self._log_rename():
                    self._open_log()
                else:
                    # Recover from external file modification
                    position = self._get_file_position()
                    self._set_file_position(0, FILE_END)
                    file_size = self._get_file_position()

                    if file_size < position:
                        # File has been externaly modified
                        position = 0
                    self._set_file_position(position)
                idle_cnt = 0
            else:
                # To reset end-of-line error
                self._set_file_position(self._get_file_position())

        self._update_state(self.real_name, self._get_file_position())
        return lines


    def _send_lines(self, lines):
        """ Sends lines. """
        for line in lines:
            if not line:
                continue
            line = self.entry_filter(line)
            if not line:
                continue
            if self.config.debug_events:
                sys.stderr.write("\n")
                sys.stderr.write(line)
            line = self.entry_formatter(line)
            if not line:
                continue
            self.transport.send(line)


    def close(self):
        """Closes the follower by setting the shutdown flag and waiting for the
        worker thread to stop."""
        self._shutdown = True
        self._worker.join(FOLLOWER_JOIN_INTERVAL)


    def monitorlogs(self):
        """ Opens the log file and starts to collect new events. """
        # If there is a predefined state, try to load it up
        state = self.get_state()
        self._open_log(state['filename'], state['position'])
        while not self._shutdown:
            try:
                lines = self._get_lines()
                try:
                    self._send_lines(lines)
                except IOError as error:
                    if self.config.debug:
                        log.log.debug("IOError: %s", error)
                    self._open_log()
                except UnicodeError:
                    log.log.warn("UnicodeError sending lines `%s'", lines, exc_info=True)
                except Exception as error:
                    log.log.error("Caught unknown error `%s' while sending lines %s",
                                  error, lines, exc_info=True)
            except Exception as error:
                log.log.error("Caught unknown error `%s' while sending line", error, exc_info=True)
        if self._file:
            self._update_state(self.real_name, self._get_file_position())
        self._close_log()


class MultilogFollower(object):
    """
    The FollowMultilog is responsible for handling those logs that were set-up using the
    '--multilog' option and that may have a wildcard in the pathname.
    In which case multiple local (log) files will be followed, but with all the new events
    from all the files forwarded to the same single log in the logentries infrastructure.
    """
    def __init__(self,
                 name,
                 entry_filter,
                 entry_formatter,
                 transport,
                 states,
                 config,
                 max_num_followers=MAX_FILES_FOLLOWED):
        """ Initializes the FollowMultilog. """
        self.name = name
        self.flush = True
        self.entry_filter = entry_filter
        self.entry_formatter = entry_formatter
        self.transport = transport
        self.config = config

        self._states = states
        self._shutdown = False
        self._max_num_followers = max_num_followers
        self._followers = []
        self._worker = threading.Thread(target=self.supervise_followers, name=self.name)
        self._worker.daemon = True
        self._worker.start()

    def _file_test(self, candidate):
        """
        Only regular files passed
        """
        # Fail if a symbolic link
        if os.path.islink(candidate):
            return False
        # Fail if not a regular file (passes links!)
        if not os.path.isfile(candidate):
            return False
        return True

    def _append_followers(self, add_files, states=None):
        if not states:
            states = {}
        for filename in add_files:
            if len(self._followers) < self._max_num_followers:
                follower = Follower(filename,
                                    self.entry_filter,
                                    self.entry_formatter,
                                    self.transport,
                                    states.get(filename),
                                    True)
                self._followers.append(follower)
                if self.config.debug_multilog:
                    sys.stderr.write("Number of followers increased to: %s" % len(self._followers))
            else:
                log.log.debug("Warning: Allowed maximum of files that can be followed reached")
                break

    def _remove_followers(self, removed_files):
        for follower in self._followers:
            if follower.name in removed_files:
                follower.close()
                self._followers.remove(follower)
                if self.config.debug_multilog:
                    sys.stderr.write("Number of followers decreased to: %s" %len(self._followers))

    def close(self):
        """
        Stops all FollowMultilog activity, and then loops through list of existing
        followers to close each one - then waits for the worker thread to stop.
        """
        self._shutdown = True
        # Run through list of followers closing each one
        for follower in self._followers:
            follower.close()
        self._worker.join(FOLLOWMULTI_JOIN_INTERVAL)

    def supervise_followers(self):
        """
         Instantiates a Follower object for each file found - all log events from all
         files are forwarded to the same log in the lE infrastructure
        """
        try:
            start_set = set([filename for filename in glob.glob(self.name)])

            if len(start_set) == 0:
                log.log.error("FollowMultilog: no files found in OS to be followed")
            else:
                self._append_followers(start_set, self._states)

        except os.error:
            log.log.error("Error: FollowerMultiple glob has failed")

        while not self._shutdown:
            time.sleep(RETRY_GLOB_INTERVAL)
            try:
                current_set = set([filename for filename in glob.glob(self.name)])
            except os.error:
                log.log.error("Error: FollowerMultiple glob has failed")
            followed_files = [follower.name for follower in self._followers]
            added_files = [filename for filename in current_set if not filename in followed_files]
            self._append_followers(added_files)
            removed_files = [filename for filename in followed_files if not filename in current_set]
            self._remove_followers(removed_files)
