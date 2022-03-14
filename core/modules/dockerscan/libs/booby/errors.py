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

"""The `errors` module contains all exceptions used by Booby."""


class BoobyError(Exception):
    """Base class for all Booby exceptions."""

    pass


class FieldError(BoobyError):
    """This exception is used as an equivalent to :class:`AttributeError`
    for :mod:`fields`.

    """

    pass


class ValidationError(BoobyError):
    """This exception should be raised when a `value` doesn't validate.
    See :mod:`validators`.

    """

    pass


class EncodeError(BoobyError):
    pass


class DecodeError(BoobyError):
    pass
