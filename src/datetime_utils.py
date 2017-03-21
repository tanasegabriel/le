"""Datetime Utils Module"""
from __future__ import absolute_import

import datetime
import re
import string
import time

from logentries.constants import DAY, MON, YEAR, SEC, MIN, HOUR
from logentries.utils import die


def date_patterns():
    """ Generates date patterns of the form [day<->month year?].
    """
    for year in [' %Y', ' %y']:
        for mon in ['%b', '%B', '%m']:
            yield ['%%d %s%s' % (mon, year), DAY, []]
            yield ['%s %%d%s' % (mon, year), DAY, []]
    for mon in ['%b', '%B']:  # Year empty
        yield ['%%d %s' % (mon), DAY, [YEAR]]
        yield ['%s %%d' % (mon), DAY, [YEAR]]
    yield ['%%Y %%d %s' % (mon), DAY, []]
    yield ['%%Y %s %%d' % (mon), DAY, []]
    yield ['%Y %m %d', DAY, []]


def time_patterns(c_cols):
    """Generates time patterns of the form [hour:min:sec?] including empty
    time.
    """
    if c_cols >= 2:
        yield ['%H:%M:%S', SEC, []]
    if c_cols >= 1:
        yield ['%H:%M', MIN, []]
        yield ['%I:%M%p', MIN, []]
    yield ['%I%p', HOUR, []]


def datetime_patterns(c_cols):
    """Generates combinations of date and time patterns.
    """
    # Generate dates only
    for date_pattern in date_patterns():
        yield date_pattern

    # Generate combinations
    for time_pattern in time_patterns(c_cols):
        for date_pattern in date_patterns():
            yield ['%s %s' % (date_pattern[0], time_pattern[0]), time_pattern[1], date_pattern[2]]
            yield ['%s %s' % (time_pattern[0], date_pattern[0]), time_pattern[1], date_pattern[2]]
        yield [time_pattern[0], time_pattern[1], [YEAR, MON, DAY]]


def timestamp_patterns(sample):
    """Generates all timestamp patterns we can handle. It is constructed by
    generating all possible combinations of date, time, day name and zone. The
    pattern is [day_name? date<->time zone?] plus simple date and time.
    """
    # All timestamps variations
    day_name = ''
    if len(sample) > 0:
        if sample[0] in string.ascii_letters:
            day_name = '%a '
    c_cols = sample.count(':')
    for zone in ['', ' %Z', ' %z']:
        for date_time in datetime_patterns(c_cols):
            yield ['%s%s%s'
                   % (day_name, date_time[0], zone), date_time[1], date_time[2]]


def timestamp_group(text):
    """Returns a tuple [timestamp, range] which corresponds to the date and
    time given. Exists on parse error.
    """
    timep = re.sub(r' +', ' ', re.sub(r'[-,./]', ' ', text)).strip()
    start_tuple = None
    for pattern in timestamp_patterns(timep):
        resolution, filling = pattern
        try:
            start_tuple = time.strptime(timep, pattern[0])
            break
        except ValueError:
            pass
    if not start_tuple:
        die("Error: Date '%s' not recognized" % text)

    today = datetime.date.today()
    # Complete filling
    if YEAR in filling:
        start_tuple.rm_year = today.year
    if MON in filling:
        start_tuple.rm_month = today.month
    if DAY in filling:
        start_tuple.rm_day = today.day
    return [int(time.mktime(start_tuple)) * 1000, resolution]


def timestamp_range(text):
    """Identifies range in the text given. Returns -1 if the range has not been
    identified.  """

    # Parse range
    match = re.match(r'^(last)?\s*(\d+)?\s*'
                     r'(s|sec|second|m|min|minute|h|hour|d|day|mon|month|y|year)s?$',
                     text.strip())
    if not match:
        return -1
    count = match.group(2)  # Count of time frames
    time_frame = match.group(3)

    if count:
        count = int(count)
    else:
        count = 1

    f_groups = [
        [['s', 'sec', 'second'], SEC],
        [['m', 'min', 'minute'], MIN],
        [['h', 'hour'], HOUR],
        [['d', 'day'], DAY],
        [['mon', 'month'], MON],
        [['y', 'year'], YEAR],
    ]
    for time_frame_groups in f_groups:
        if time_frame in time_frame_groups[0]:
            return count * time_frame_groups[1]
    return -1


def parse_timestamp_range(text):
    """Parses the time range given and return start-end pair of timestamps.

    Recognized structures are:
    t|today
    y|yesterday
    last? \\d* (m|min|minute|h|hour|d|day|mon|month|y|year) s?
    range
    datetime
    datetime -> range
    datetime -> datetime
    """

    text = text.strip()
    # No time frame
    if text == '':
        return [0, 9223372036854775807]

    # Day spec
    now = datetime.datetime.now()
    if text in ['t', 'today']:
        today = int(time.mktime(datetime.datetime(now.year, now.month, now.day).timetuple())) * 1000
        return [today, today + DAY]
    if text in ['y', 'yesterday']:
        yesterday = int(time.mktime((datetime.datetime(now.year, now.month, now.day) -
                                     datetime.timedelta(days=1)).timetuple())) * 1000
        return [yesterday, yesterday + DAY]

    # Range spec
    parts = text.split('->')
    ts_range = timestamp_range(parts[0])
    if (ts_range != -1 and len(parts) > 1) or len(parts) > 2:
        die("Error: Date and range '%s' has invalid structure" % text)
    if ts_range != -1:
        now = int(time.time() * 1000)
        return [now - ts_range, now]

    # Date spec
    start_group = timestamp_group(parts[0])
    start = start_group[0]
    end = start + start_group[1]

    if len(parts) > 1:
        end_range = timestamp_range(parts[1])
        if end_range != -1:
            end = start + end_range
        else:
            end_group = timestamp_group(parts[1])
            end = end_group[0] + end_group[1]

    return [start, end]
