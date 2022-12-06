#!/usr/bin/python3
#
# Copyright (c) 2014 The FreeBSD Foundation
# Copyright 2014 John-Mark Gurney
# All rights reserved.
# Copyright 2019 Enji Cooper
#
# This software was developed by John-Mark Gurney under
# the sponsorship from the FreeBSD Foundation.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import os

class KATParser:
    def __init__(self, fname, fields):
        self.fields = set(fields)
        self._pending = None
        self.fname = fname
        self.fp = None

    def __enter__(self):
        self.fp = open(self.fname)
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        if self.fp is not None:
            self.fp.close()

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            while True:
                didread = False
                if self._pending is not None:
                    i = self._pending
                    self._pending = None
                else:
                    i = self.fp.readline()
                    didread = True

                if didread and not i:
                    return

                if not i.startswith('#') and i.strip():
                    break

            if i[0] == '[':
                yield i[1:].split(']', 1)[0], self.fielditer()
            else:
                raise ValueError('unknown line: %r' % repr(i))

    def eatblanks(self):
        while True:
            line = self.fp.readline()
            if line == '':
                break

            line = line.strip()
            if line:
                break

        return line

    def fielditer(self):
        while True:
            values = {}

            line = self.eatblanks()
            if not line or line[0] == '[':
                self._pending = line
                return

            while True:
                try:
                    f, v = line.split(' =')
                except:
                    if line == 'FAIL':
                        f, v = 'FAIL', ''
                    else:
                        print('line:', repr(line))
                        raise
                v = v.strip()

                if f in values:
                    raise ValueError('already present: %r' % repr(f))
                values[f] = v
                line = self.fp.readline().strip()
                if not line:
                    break

            # we should have everything
            remain = self.fields.copy() - set(values.keys())
            # XXX - special case GCM decrypt
            if remain and not ('FAIL' in values and 'PT' in remain):
                raise ValueError('not all fields found: %r' % repr(remain))

            yield values

