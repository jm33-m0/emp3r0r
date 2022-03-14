# -*- coding: utf-8 -*-
#
# Copyright 2014 Jaime Gil de Sagredo Luna
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections

from . import mixins, errors
from .helpers import nullable


class Encoder(object):
    def __call__(self, value):
        return self.encode(value)


class Model(Encoder):
    @nullable
    def encode(self, value):
        return value.encode()


class List(Encoder):
    def __init__(self, *encoders):
        self._encoders = encoders

    @nullable
    def encode(self, value):
        if not isinstance(value, collections.MutableSequence):
            raise errors.EncodeError()

        result = []
        for item in value:
            for encoder in self._encoders:
                item = encoder(item)

            result.append(item)

        return result


class DateTime(Encoder):
    def __init__(self, format=None):
        self._format = format

    @nullable
    def encode(self, value):
        if self._format is None:
            return value.isoformat()

        return value.strftime(self._format)


class Collection(List):
    def __init__(self):
        super(Collection, self).__init__(Model())
