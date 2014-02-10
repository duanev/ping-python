#
# Ping - bounce ICMP identify packets off remote hosts
#
# The author of this code (a) does not expect anything from you, and (b)
# is not responsible for any of the problems you may have using this code.
#
# requires: python2
# tested on: Arch Linux (as of feb 2014)

__date__ = "2014/02/10"
__version__ = "v0.91"

import sys
import time

def dumphex(s):
    def prntabl(c):
        return c if ord(c) >= 32 and ord(c) <= 127 else '.'

    bytes = map(lambda x: '%.2x' % x, map(ord, s))
    if len(s) >= 16:
        for i in xrange(0, len(bytes) / 16):
            print '    %-48s %s' % (' '.join(bytes[i*16:(i+1)*16]),
                                   ''.join(map(prntabl, s[i*16:(i+1)*16])))
        print '    %-48s %s' % (' '.join(bytes[(i+1)*16:]),
                                ''.join(map(prntabl, s[(i+1)*16:])))
    else:
        print '    %-48s %s' % (' '.join(bytes),
                                ''.join(map(prntabl, s)))

def logtime():
    return time.strftime("%H:%M:%S ")

# -----------------------------------------------------------------------
# A thread based polling service with pause, kill and a few other goodies.
# Since it polls the function passed, the function needs to return
# as soon as possible.

import threading

ST_KILLED  = 0
ST_PAUSED  = 1
ST_RUNNING = 2
ST_names = { 0:"killed", 1:"paused", 2:"running" }

class Poll(threading.Thread):
    def __init__(self, func, args=(), name=None, period=0.1):
        # we need a tuple here
        if type(args) != type((1,)):
            args = (args,)
        self._function = func
        self._args = args
        self.period = period
        threading.Thread.__init__(self, target=func, name=name, args=())
        self._uptime = time.time()
        self._state = ST_RUNNING
        self.start()

    def run(self):
        while self._state != ST_KILLED:
            if self._state == ST_RUNNING:
                self._function(self._args)
            time.sleep(self.period)

    def kill(self):
        self._state = ST_KILLED

    def pause(self):
        if self._state == ST_RUNNING:
            self._state = ST_PAUSED

    def resume(self):
        if self._state == ST_PAUSED:
            self._state = ST_RUNNING

    def uptime(self):
        return time.time() - self._uptime

    def state(self):
        return ST_names[self._state]

    def __str__(self):
        return self.getName()

def thread_list():
    """Doesn't list mainthread"""
    return filter(lambda x: x.getName() != "MainThread", threading.enumerate())

def tlist():
    """Human readable version of thread_list()"""
    for t in thread_list(): 
        if isinstance(t, Poll):
            print "%-16s  %-8s  %4.3f" % (t, t.state(), t.uptime())

def killall():
    for t in thread_list(): 
        t.kill()

# -----------------------------------------------------------------------
# ping from scratch

import os
import struct
import socket

class PingService(object):
    """Send out icmp ping requests at 'delay' intervals and
       watch for replies.  The isup() method can be used by
       other threads to check stats of the remote host.
       And yes you need root/administrator privs
       to use the icmp ping service.
    """
    def __init__(self, host, delay=1.0, its_dead_jim=4, verbose=False):
        self.host = host
        self.delay = delay
        self.verbose = verbose
        self.pronouncement_delay = its_dead_jim * delay
        socket.setdefaulttimeout(0.01)
        #print "timeout", socket.getdefaulttimeout()
        self._isup = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.getprotobyname('icmp'))
        try:
            self.sock.connect((host, 22))
        except socket.gaierror, ex:
            print "ping thread cannot connect to %s:" % host, ex[1]
            self.sock.close()
            return

    def start(self):
        self.seq = 0
        self.pid = os.getpid()
        self.last_heartbeat = 0
        # send a ping right away
        self.time_to_send = time.time()
        self.thread = Poll(self.ping, (None), name=self.host)
        #retry = 10
        ## retry for 2 seconds before letting caller deal with a down state
        #while retry > 0 and not self._isup:
        #    time.sleep(0.2)
        #    retry -= 1

    def icmp_checksum(self, pkt):
        n = len(pkt)
        two_bytes = struct.unpack("!%sH" % (n/2), pkt)
        chksum = sum(two_bytes)
        if n & 1 == 1:
            chksum += pkt[-1]
        chksum = (chksum >> 16) + (chksum & 0xffff)
        chksum += chksum >> 16
        return ~chksum & 0xffff

    def icmp_create(self, data):
        fmt = "!BBH"
        args = [8, 0, 0]
        if data and len(data) > 0:
            fmt += "%ss" % len(data)
            args.append(data)
        args[2] = self.icmp_checksum(struct.pack(fmt, *args))
        return struct.pack(fmt, *args)

    def icmp_parse(self, pkt):
        """Parse ICMP packet"""
        string_len = len(pkt) - 4 # Ignore IP header
        fmt = "!BBH"
        if string_len:
            fmt += "%ss" % string_len
        unpacked_packet = struct.unpack(fmt, pkt)
        typ, code, chksum = unpacked_packet[:3]
        if self.icmp_checksum(pkt) != 0:
            print logtime() + "%s reply checksum is not zero" % self.host
        try:
            data = unpacked_packet[3]
        except IndexError:
            data = None
        return typ, data


    def ping(self, args):
        now = time.time()
        if now >= self.time_to_send:
            # send ping packet 
            self.seq += 1
            self.seq &= 0xffff
            pdata = struct.pack("!HHd", self.pid, self.seq, now)
            self.sock.send(self.icmp_create(pdata))
            self.time_to_send = now + self.delay

        if self._isup and now - self.last_heartbeat > self.pronouncement_delay:
            self._isup = False
            self.offline()

        try:
            rbuf = self.sock.recv(10000)
            now = time.time()       # refresh 'now' to make rtt more accurate
        except socket.timeout:
            return

        if len(rbuf) <= 20:
            print logtime() + "%s truncated reply" % self.host
            return

        # parse ICMP packet; ignore IP header
        typ, rdata = self.icmp_parse(rbuf[20:])

        if typ != 0:
            print logtime() + "%s packet not an echo reply (%d) " % (
                                    self.host, typ)
            dumphex(rbuf)
            return

        if not rdata:
            print logtime() + "%s packet contains no data" % (self.host)
            return

        if len(rdata) != 12:
            # print logtime() + "%s not our ping (len=%d)" % (
            #                        self.host, len(rdata))
            return

        # parse ping data
        (ident, seqno, timestamp) = struct.unpack("!HHd", rdata)

        if ident != self.pid:
            print logtime() + "%s not our ping (ident=%d)" % (
                                    self.host, ident)
            return

        if seqno != self.seq:
            print logtime() + "%s sequence out of order got(%d) expected(%d)" % (
                                    self.host, seqno, self.seq)
            return

        if rdata and len(rdata) >= 8:
            #print '.'
            self.last_heartbeat = now

            if not self._isup:
                self._isup = True
                self.online()

            if self.verbose:
                str = "%d bytes from %s: seq=%u" % (
                      len(rbuf),
                      socket.inet_ntop(socket.AF_INET, rbuf[12:16]), self.seq)

                # calculate rounttrip time
                rtt = now - timestamp
                rtt *= 1000
                # note that some boxes that run python
                # can't resolve milisecond time deltas ...
                if rtt > 0:
                    str += ", rtt=%.1f ms" % rtt

                print str

    def isup(self):
        return self._isup

    def online(self):
        print logtime() + "%s is up" % self.host

    def offline(self):
        print logtime() + "%s is down" % self.host

    def stop(self):
        if 'thread' in dir(self):
            self.thread.kill()
        self.sock.close()

# ----------------------------------------------------------------------------
# demonstrate PingService: heartbeat one or more hosts every 4 seconds
# (yup, this can be abusive)

if __name__ == "__main__":
    import traceback

    if len(sys.argv) < 2:
        print "usage: python ping.py <ip|mask|range> [<ip|mask|range> ...]"
        sys.exit(1)

    def ip_range(input_string):
        # (Blender's answer - http://stackoverflow.com/questions/20525330)
        octets = input_string.split('.')
        chunks = [map(int, octet.split('-')) for octet in octets]
        ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]

        import itertools
        for address in itertools.product(*ranges):
            yield '.'.join(map(str, address))

    def mask_to_range(input_string):
        idx = input_string.find('/')
        bits = int(input_string[idx+1:])
        ip = input_string[:idx].rstrip('.').split('.')
        while len(ip) < 4:
            ip.append(0)
        result = []
        while bits >= 8:
            result.append(ip.pop(0))
            bits -= 8
        if bits > 0:
            lo = int(ip[0]) & (0xff ^ (0xff >> bits))
            hi = int(ip[0]) | (0xff >> bits)
            result.append('%d-%d' % (lo, hi))
        while len(result) < 4:
            result.append('0-255')
        return '.'.join(result)

    addrs = []
    for arg in sys.argv[1:]:
        if arg.find('-') > 0 \
        and arg.replace('.', '').replace('-', '').isdigit():
            addrs += [addr for addr in ip_range(arg)]

        elif arg.find('/') > 0 \
        and arg.replace('.', '').replace('/', '').isdigit():
            addrs += [addr for addr in ip_range(mask_to_range(arg))]

        elif arg.replace('.', '').isdigit():
            addrs.append(arg)

        else:
            print "ip [%s] must be a range, a mask, or a single ip" % arg
            sys.exit(1)

    if len(addrs) == 0:
        sys.exit(0)

    ping = []
    for addr in addrs:
        # pass over ips that end with .0
        if int(addr.rsplit('.', 1)[-1]) == 0:
            print "ignoring", addr
            continue

        try:
            ping_svc = PingService(addr, delay=4)
        except socket.error:
            t, v, tb = sys.exc_info()
            print addr, ':', str(v)
            continue

        # don't ping ourself
        if addr == ping_svc.sock.getsockname()[0]:
            ping_svc.stop()
            print "localhost is", addr
            continue

        ping.append(ping_svc)

    print "%d address%s" % (len(ping), ['', 'es'][len(ping) > 1])
    if len(ping) == 0:
        sys.exit(0)

    try:
        for p in ping:
            p.start()

        while True:
            time.sleep(10)

    except KeyboardInterrupt:
        print "---- running threads ----"
        tlist()
        print "----"

    except:
        t, v, tb = sys.exc_info()
        traceback.print_exception(t, v, tb)

    for p in ping:
        p.stop()

    sys.exit(0)


# ex: set tabstop=8 expandtab softtabstop=4 shiftwidth=4:
