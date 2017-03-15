"""Metrics Module"""
#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 et:

#pylint: disable=redefined-outer-name, invalid-name
#pylint: disable=wrong-import-order, wrong-import-position
from __future__ import absolute_import

import re
import sys
import threading
import time
import traceback

import configparser as ConfigParser
from . import formats
from .__init__ import __version__
from .utils import report

# Try to import psutils
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# Main section name
SECT = 'Main'
# Common option prefix
PREFIX = 'metrics-'

# Configuration names
TOKEN = 'token'
INTERVAL = 'interval'
CPU = 'cpu'
VCPU = 'vcpu'
MEM = 'mem'
SWAP = 'swap'
NET = 'net'
DISK = 'disk'
SPACE = 'space'
PROCESS = 'process'


def _psutil_cpu_count():
    """Replaces cpu_count which is missing in older version."""
    try:
        return psutil.NUM_CPUS
    except AttributeError:
        return psutil.cpu_count()

class CpuMetrics(object):
    """CPU Metrics"""
    def __init__(self, per_core, interval, transport, formatter):
        self._per_core = per_core
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None
        self._vcpus = _psutil_cpu_count()

    @staticmethod
    def construct(curr, last, vcpus, per_core, index=-1):
        """Construct aggregated CPU metrics"""
        user = curr.user - last.user
        nice = curr.nice - last.nice
        system = curr.system - last.system
        idle = curr.idle - last.idle
        total_idle = idle
        iowait = curr.iowait - last.iowait
        irq = curr.irq - last.irq
        softirq = curr.softirq - last.softirq
        try:
            steal = curr.steal - last.steal
            guest = curr.guest - last.guest
            guest_nice = curr.guest_nice - last.guest_nice
        except AttributeError:
            steal = 0
            guest = 0
            guest_nice = 0
        total_cpu = user + nice + system + idle + iowait + \
            irq + softirq + steal
        if per_core:
            fraction = vcpus / total_cpu * 100
        else:
            fraction = 1 / total_cpu * 100
        user *= fraction
        nice *= fraction
        system *= fraction
        usage = (total_cpu - total_idle) * fraction
        idle = 100.0 - usage
        iowait *= fraction
        irq *= fraction
        softirq *= fraction
        steal *= fraction
        guest *= fraction
        guest_nice *= fraction
        if index != -1:
            xvcpu = 'vcpu=%d ' % index
        else:
            xvcpu = ''
        return '%suser=%.1f nice=%.1f system=%.1f ' \
               'usage=%.1f idle=%.1f iowait=%.1f ' \
               'irq=%.1f softirq=%.1f steal=%.1f ' \
               'guest=%.1f guest_nice=%.1f vcpus=%d\n' \
               % (xvcpu, user, nice, system,
                  usage, idle, iowait,
                  irq, softirq, steal,
                  guest, guest_nice, vcpus)

    def collect(self):
        """Collect aggregated CPU metrics"""
        curr = psutil.cpu_times()
        if self._last:
            line = CpuMetrics.construct(
                curr, self._last, self._vcpus, self._per_core)
            self._transport.send(self._formatter.format_line(line, msgid='cpu'))
        self._last = curr


class VcpuMetrics(object):
    """VCPU Metrics"""
    def __init__(self, interval, transport, formatter):
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._vcpus = _psutil_cpu_count()
        self._last = None

    def collect(self):
        """Collect per-CPU metrics"""
        try:
            curr = psutil.cpu_times(percpu=True)
        except TypeError:
            return
        last = self._last
        if last:
            for index in range(self._vcpus):
                line = CpuMetrics.construct(
                    curr[index], last[index], self._vcpus, True, index)
                self._transport.send(
                    self._formatter.format_line(line, msgid='vcpu'))
        self._last = curr


class MemMetrics(object):
    """Memory Metrics"""
    def __init__(self, interval, transport, formatter):
        self._interval = interval
        self._transport = transport
        self._formatter = formatter

    def collect(self):
        """Collect memory metrics"""
        try:
            mem = psutil.virtual_memory()
        except AttributeError:
            return
        total = float(mem.total)
        line = 'total=%d available=%.1f used=%.1f ' \
               'free=%.1f active=%.1f inactive=%.1f ' \
               'buffers=%.1f cached=%.1f\n' \
               % (mem.total, mem.available / total * 100, mem.used / total * 100,
                  mem.free / total * 100, mem.active / total * 100, mem.inactive / total * 100,
                  mem.buffers / total * 100, mem.cached / total * 100)

        self._transport.send(self._formatter.format_line(line, msgid='mem'))


class SwapMetrics(object):
    """Swap Metrics"""
    def __init__(self, interval, transport, formatter):
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None

    def _construct(self, curr, last):
        """Construct swap metrics"""
        total = float(curr.total)
        sin = curr.sin - last.sin
        sout = curr.sout - last.sout
        if curr.total != 0:
            used = curr.used / total * 100
            free = curr.free / total * 100
        else:
            used = 0
            free = 0
        return 'total=%d used=%.1f free=%.1f in=%d out=%d\n' \
               % (curr.total, used, free, sin, sout)

    def collect(self):
        """Collect swap metrics"""
        try:
            curr = psutil.swap_memory()
        except AttributeError:
            return
        if self._last:
            line = self._construct(curr, self._last)
            self._transport.send(self._formatter.format_line(line, msgid='swap'))
        self._last = curr


class DiskIoMetrics(object):
    """Disk IO Metrics"""
    def __init__(self, devices, interval, transport, formatter):
        self._parse_devices(devices)
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None
        self._last_sum = None

    def _parse_devices(self, devices):
        """Parse devices"""
        xdevices = set(devices.split())
        self._sum = 'sum' in xdevices
        self._all = 'all' in xdevices
        self._devices = frozenset(xdevices - set(['sum', 'all']))

    def _construct(self, device_name, curr, last):
        """Construct diskIO metrics"""
        line = 'device=%s reads=%d writes=%d bytes_read=%d ' \
               'bytes_write=%d time_read=%d time_write=%d\n' \
               % (quote(device_name),
                  curr.read_count - last.read_count,
                  curr.write_count - last.write_count,
                  curr.read_bytes - last.read_bytes,
                  curr.write_bytes - last.write_bytes,
                  curr.read_time - last.read_time,
                  curr.write_time - last.write_time)
        self._transport.send(self._formatter.format_line(line, msgid='disk'))

    def collect(self):
        """Collect metrics for all devices"""
        if self._sum:
            try:
                curr = psutil.disk_io_counters(perdisk=False)
            except Exception:
                # Not enough permissions
                curr = self._last_sum = None
            if self._last_sum:
                self._construct('sum', curr, self._last_sum)
            self._last_sum = curr

        # Collect metrics for each device
        if self._all or self._devices:
            try:
                curr_all = psutil.disk_io_counters(perdisk=True)
            except Exception:
                # Typically not enough permissions
                curr_all = self._last = None
            if self._last:
                for curr_device in curr_all:
                    if self._all or curr_device in self._devices:
                        try:
                            curr = curr_all[curr_device]
                            last = self._last[curr_device]
                        except KeyError:
                            continue
                        self._construct(curr_device, curr, last)
            self._last = curr_all


class DiskSpaceMetrics(object):
    """Disk Space Metrics"""
    def __init__(self, paths, interval, transport, formatter):
        self._parse_paths(paths)
        self._interval = interval
        self._transport = transport
        self._formatter = formatter

    def _parse_paths(self, paths):
        """Helper method to parse paths"""
        self._paths = frozenset(paths.split())

    def collect(self):
        """Collect disk space metrics"""
        for path in self._paths:
            try:
                curr = psutil.disk_usage(path)
                if curr.total != 0:
                    used = curr.used / float(curr.total) * 100
                    free = curr.free / float(curr.total) * 100
                else:
                    used = 0
                    free = 0
                line = 'path=%s size=%d used=%.1f free=%.1f\n' \
                       % (quote(path), curr.total, used, free)
                self._transport.send(self._formatter.format_line(line, msgid='space'))
            except Exception:
                # Not enough permissions
                continue


class NetMetrics(object):
    """Network Metrics"""
    def __init__(self, nets, interval, transport, formatter):
        self._parse_nets(nets)
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._last = None
        self._last_sum = None

    def _parse_nets(self, nets):
        """Parse nets"""
        xnets = set(nets.split())
        self._sum = 'sum' in xnets
        self._select = 'select' in xnets
        self._all = 'all' in xnets
        self._nets = frozenset(xnets - set(['sum', 'select', 'all']))

    def _construct(self, net, curr, last):
        """Construct network metrics"""
        sent_bytes = curr.bytes_sent - last.bytes_sent
        recv_bytes = curr.bytes_recv - last.bytes_recv
        sent_packets = curr.packets_sent - last.packets_sent
        recv_packets = curr.packets_recv - last.packets_recv
        err_in = curr.errin - last.errin
        err_out = curr.errout - last.errout
        drop_in = curr.dropin - last.dropin
        drop_out = curr.dropout - last.dropout
        line = 'net=%s bytes_sent=%d bytes_recv=%d packets_sent=%d ' \
               'packets_recv=%d err_in=%d err_out=%d drop_in=%d drop_out=%d\n' \
               % (quote(net), sent_bytes, recv_bytes, sent_packets,
                  recv_packets, err_in, err_out, drop_in, drop_out)
        self._transport.send(self._formatter.format_line(line, msgid='net'))

    @staticmethod
    def _selected(net):
        for prefix in ['eth', 'en', 'ww', 'wl', 'venet', 'veth']:
            if net.startswith(prefix):
                return True
        return False

    def collect(self):
        """Collect network metrics"""
        if self._sum:
            counters = psutil.net_io_counters(pernic=False)
            if self._last_sum:
                self._construct('sum', counters, self._last_sum)
            self._last_sum = counters

        # Per-interface metrics
        if self._all or self._select or self._nets:
            counters = psutil.net_io_counters(pernic=True)
            if self._last:
                for net in counters:
                    if self._all or net in self._nets \
                            or (self._select and self._selected(net)):
                        try:
                            self._construct(
                                net, counters[net], self._last[net])
                        except Exception:
                            pass  # Typically not enough permissions
            self._last = counters


class ProcMetrics(object):
    """Process Metrics"""
    def __init__(self, name, pattern, token, interval, transport, formatter):
        self._name = name
        self._pattern = pattern
        self._token = token
        self._interval = interval
        self._transport = transport
        self._formatter = formatter
        self._proc = None
        self._last_cpu = None
        self._last_io = None
        try:
            self._total = psutil.virtual_memory().total
        except AttributeError:
            self._total = 0

    def _find_proc(self):
        for proc in psutil.process_iter():
            cmdline = ' '.join(proc.cmdline())
            if cmdline and cmdline.find(self._pattern) != -1:
                return proc

    def _get_io_counters(self):
        try:
            return self._proc.io_counters()
        except Exception:
            return None

    def _get_fds(self):
        try:
            return self._proc.num_fds()
        except Exception:
            return None

    def collect(self):
        """Collect process metrics"""
        if not self._total:
            return
        if self._proc and not self._proc.is_running():
            self._proc = None
        if not self._proc:
            self._proc = self._find_proc()
        if not self._proc:
            return

        proc = self._proc
        cpu = proc.cpu_times()
        mem = proc.memory_info()
        io = self._get_io_counters()
        fds = self._get_fds()

        if self._last_cpu:
            if io and self._last_io:
                lio = self._last_io
                io_line = ' reads=%d writes=%d bytes_read=%d bytes_write=%d' \
                          % (io.read_count - lio.read_count,
                             io.write_count - lio.write_count,
                             io.read_bytes - lio.read_bytes,
                             io.write_bytes - lio.write_bytes)
            else:
                io_line = ''

            if fds:
                fds_line = ' fds=%d' % fds
            else:
                fds_line = ''

            lcpu = self._last_cpu
            cpu_user = float(cpu.user - lcpu.user) / self._interval * 100
            cpu_system = float(cpu.system - lcpu.system) / self._interval * 100
            line = 'cpu_user=%.1f cpu_system=%.1f%s%s ' \
                   'mem=%.1f total=%d rss=%d vms=%d\n' \
                   % (cpu_user, cpu_system, io_line, fds_line, proc.memory_percent(),
                      self._total, mem.rss, mem.vms)
            self._transport.send(
                self._formatter.format_line(line, msgid=self._name, token=self._token))
        self._last_cpu = cpu
        self._last_io = io


class Metrics(object):
    """Metrics collecting class."""
    def __init__(self, conf, default_transport, formatter, debug):
        """Creates an instance of metrics from the configuration."""
        self._ready = False
        self._token = conf.token

        if debug and not default_transport:
            self._transport = StderrTransport(None)
        elif debug:
            self._transport = StderrTransport(default_transport.get())
        else:
            self._transport = default_transport.get()
        self._formatter = formatter
        self._debug = debug

        self._timer = None
        self._shutdown = False
        self._interval = self._parse_interval(conf.interval)
        if self._interval == 0:
            report("Warning: Cannot instantiate metrics, invalid interval `%s'." % conf.interval)

        if PSUTIL_AVAILABLE:
            self._items = self._instantiate_system(conf, debug) + \
                          self._instantiate_processes(conf, debug)
        else:
            if debug:
                report("Warning: Cannot instantiate system metrics, "
                       "psutil library is not available.")
            self._items = []
            return

        self._ready = True

    def _parse_interval(self, interval):
        """Parse the given interval"""
        if len(interval) == 0:
            return 5  # Default is 5 second interval
        unit = interval[-1:]
        try:
            value = int(interval[:-1])
        except ValueError:
            return 0
        if unit == 's':
            pass
        elif unit == 'm':
            value *= 60
        else:
            return 0
        return value

    def _instantiate_system(self, conf, debug):
        """Instantiate system metrics if token specified"""
        if not conf.token:
            if debug:
                report("Warning: Cannot instantiate system metrics, token not specified.")
            return []
        items = []
        if conf.cpu:
            if conf.cpu in ['core', 'system']:
                items.append(CpuMetrics(conf.cpu == 'core', self._interval,
                                        self._transport, self._formatter))
            else:
                report("Unrecognized cpu option `%s', `core' or `system' expected" % conf.cpu)
        if conf.vcpu:
            if conf.vcpu == 'core':
                items.append(VcpuMetrics(self._interval, self._transport, self._formatter))
            else:
                report("Unrecognized vcpu option `%s', `core' expected" % conf.vcpu)
        if conf.mem:
            if conf.mem == 'system':
                items.append(MemMetrics(self._interval, self._transport, self._formatter))
            else:
                report("Unrecognized mem option `%s', `system' expected" % conf.mem)
        if conf.swap:
            if conf.swap == 'system':
                items.append(SwapMetrics(self._interval, self._transport, self._formatter))
            else:
                report("Unrecognized swap option `%s', `system' expected" % conf.swap)
        if conf.disk:
            items.append(DiskIoMetrics(conf.disk,
                                       self._interval, self._transport, self._formatter))
        if conf.space:
            items.append(DiskSpaceMetrics(conf.space,
                                          self._interval, self._transport, self._formatter))
        if conf.net:
            items.append(NetMetrics(conf.net,
                                    self._interval, self._transport, self._formatter))

        return items

    def _instantiate_processes(self, conf, debug):
        """Instantiate all processes"""
        items = []
        for process in conf.processes:
            name = process[0]
            token = process[2]
            if not token:
                if debug:
                    report("Warning: Cannot instantiate metrics for `%s', "
                           "token not specified." % name)
            else:
                items.append(ProcMetrics(name, process[1], token,
                                         self._interval, self._transport, self._formatter))

        return items

    def _schedule(self, ethalon):
        """Schedule metrics"""
        # TODO - align metrics on time boundary
        ethalon += self._interval
        next_step = (ethalon - time.time()) % self._interval
        if not self._shutdown:
            self._timer = threading.Timer(next_step, self._collect_metrics, ())
            self._timer.daemon = True
            self._timer.start()


    def _collect_metrics(self):
        """Collect metrics"""
        ethalon = time.time()

        for item in self._items:
            try:
                item.collect()
            except Exception as error:
                # Make sure we don't propagate any unexpected exceptions
                # Typically `permission denied' on hard-ended systems
                if self._debug:
                    report("Warning: `%s'" % error)
                    report(''.join(traceback.format_tb(sys.exc_info()[2])))

        self._schedule(ethalon)


    def _collect_info(self):
        """Collect agent information"""
        if self._token:
            line = "agent_version=%s\n" % __version__
            self._transport.send(self._formatter.format_line(line, msgid='start'))

    def start(self):
        """Start metrics"""
        if self._ready:
            self._schedule(time.time())
            self._collect_info()

    def cancel(self):
        """Cancel metrics"""
        if self._ready:
            self._shutdown = True
            timer = self._timer
            if timer:
                timer.cancel()


class StderrTransport(object):
    """Default transport encapsulation with additional logging to stderr."""
    def __init__(self, transport=None):
        self._transport = transport

    def get(self):
        """Get Stderr Transport"""
        return self

    def send(self, entry):
        """Send entry"""
        sys.stderr.write(entry)
        if self._transport:
            self._transport.send(entry)


class MetricsConfig(object):
    """Metrics configuration holder."""
    DEFAULTS = {
        TOKEN: '',
        INTERVAL: '5s',
        CPU: 'system',
        VCPU: '',
        MEM: 'system',
        SWAP: 'system',
        NET: 'sum',
        DISK: 'sum',
        SPACE: '/',
    }

    def __init__(self):
        # Set instance fields initialized to default values
        self.token = '' # Avoid pylint error
        for item in self.DEFAULTS:
            self.__dict__[item] = self.DEFAULTS[item]
        self.processes = []

    def load(self, conf):
        """Loads metrics configuration."""
        # Basic metrics
        for item in self.DEFAULTS:
            try:
                self.__dict__[item] = conf.get(SECT, PREFIX + item)
            except ConfigParser.NoOptionError:
                pass
        # Process metrics
        for section in conf.sections():
            if section != SECT:
                try:
                    try:
                        token = conf.get(section, PREFIX + TOKEN)
                    except ConfigParser.NoOptionError:
                        try:
                            token = conf.get(section, TOKEN)
                        except ConfigParser.NoOptionError:
                            token = ''
                    pattern = conf.get(section, PREFIX + PROCESS)
                    self.processes.append([section, pattern, token])
                except ConfigParser.NoOptionError:
                    pass

    def save(self, conf):
        """Saves all metrics conficuration."""
        # Basic metrics
        for item in self.DEFAULTS:
            conf.set(SECT, PREFIX + item, self.__dict__[item])
        # Process metrics
        for process in self.processes:
            try:
                conf.add_section(process[0])
            except ConfigParser.DuplicateSectionError:
                continue
            conf.set(process[0], PREFIX + PROCESS, process[1])
            if process[2]:
                conf.set(process[0], PREFIX + TOKEN, process[2])

# Pattern matching safe values, values that does not need to be quited
SAFE_CHARS = re.compile(r'^[a-zA-Z0-9_]*$')


def quote(text):
    """Encloses the string with quotes if needed. It does not escape
    characters."""
    if SAFE_CHARS.match(text):
        return text
    else:
        return '"%s"' % text

if __name__ == '__main__':
    metrics = None
    try:
        conf = MetricsConfig()
        conf.__dict__[VCPU] = 'core'
        conf.__dict__[NET] = 'sum all'
        conf.__dict__[DISK] = 'sum all'
        conf.__dict__[TOKEN] = 'e2b405df-858b-4148-92a5-37d06dbd50f5'
        metrics = Metrics(conf, None, formats.FormatSyslog('', 'le', ''), True)
        metrics.start()
        time.sleep(600)  # Is there a better way?
    except KeyboardInterrupt:
        sys.stderr.write("\nTerminated")

    if metrics:
        metrics.cancel()
