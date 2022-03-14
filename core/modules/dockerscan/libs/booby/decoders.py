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

import re
import datetime

from . import errors
from .helpers import nullable


class Decoder(object):
    def __call__(self, value):
        return self.decode(value)


class Model(Decoder):
    def __init__(self, model):
        self._model = model

    @nullable
    def decode(self, value):
        return self._model.decode(value)


class DateTime(Decoder):
    def __init__(self, format=None):
        self._format = format

    @nullable
    def decode(self, value):
        format = self._format_for(value)

        try:
            return datetime.datetime.strptime(value, format)
        except ValueError:
            raise errors.DecodeError()

    def _format_for(self, value):
        if self._format is not None:
            return self._format

        format = '%Y-%m-%dT%H:%M:%S'

        if self._has_microseconds(value):
            format += '.%f'

        return format

    def _has_microseconds(self, value):
        return re.match('^.*\.[0-9]+$', value) is not None


class List(Decoder):
    def __init__(self, *decoders):
        self._decoders = decoders

    def decode(self, value):
        result = []
        for item in value:
            for decoder in self._decoders:
                item = decoder(item)

            result.append(item)

        return result


class Collection(List):
    def __init__(self, model):
        super(Collection, self).__init__(Model(model))
