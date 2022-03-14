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

import functools


def nullable(method):
    """Helper decorator to make validators, encoders and decoders
    work for non required values.

    If the given `value` is not :keyword:`None` then the decorated
    method will be called as usually. If :keyword:`None` is passed
    instead nothing will be called.

    The :class:`validators.String` validator is a good example::

        class String(object):
            def validate(self, value):
                if value is not None:
                    pass # Do the validation here ...

    Now the same but using the `@nullable` decorator::

        @nullable
        def validate(self, value):
            pass # Do the validation here ...

    """

    @functools.wraps(method)
    def wrapper(self, value):
        if value is not None:
            return method(self, value)

    return wrapper
