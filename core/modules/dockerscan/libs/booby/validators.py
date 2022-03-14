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

"""The `validators` module contains a set of :mod:`fields` validators.

A validator is any callable `object` which receives a `value` as the
target for the validation. If the validation fails then should raise an
:class:`errors.ValidationError` exception with an error message.

`Validators` are passed to :class:`fields.Field` and subclasses as possitional
arguments.

"""

import re

import six
import collections
import datetime

from booby import errors
from booby.helpers import nullable


class Validator(object):
    def __call__(self, value):
        self.validate(value)

    def validate(self, value):
        raise NotImplementedError()


class Required(Validator):
    """This validator forces fields to have a value other than :keyword:`None`."""

    def validate(self, value):
        if value is None:
            raise errors.ValidationError('is required')


class In(Validator):
    """This validator forces fields to have their value in the given list.

    :param choices: A `list` of possible values.

    """

    def __init__(self, choices):
        self.choices = choices

    def validate(self, value):
        if value not in self.choices:
            raise errors.ValidationError('should be in {}'.format(self.choices))


class String(Validator):
    """This validator forces fields values to be an instance of `basestring`."""

    @nullable
    def validate(self, value):
        if not isinstance(value, six.string_types):
            raise errors.ValidationError('should be a string')


class Integer(Validator):
    """This validator forces fields values to be an instance of `int`."""

    @nullable
    def validate(self, value):
        if not isinstance(value, six.integer_types):
            raise errors.ValidationError('should be an integer')


class Float(Validator):
    """This validator forces fields values to be an instance of `float`."""

    @nullable
    def validate(self, value):
        if not isinstance(value, float):
            raise errors.ValidationError('should be a float')


class Boolean(Validator):
    """This validator forces fields values to be an instance of `bool`."""

    @nullable
    def validate(self, value):
        if not isinstance(value, bool):
            raise errors.ValidationError('should be a boolean')


class Model(Validator):
    """This validator forces fields values to be an instance of the given
    :class:`models.Model` subclass and also performs a validation in the
    entire `model` object.

    :param model: A subclass of :class:`models.Model`

    """

    def __init__(self, model):
        self.model = model

    @nullable
    def validate(self, value):
        if not isinstance(value, self.model):
            raise errors.ValidationError(
                "should be an instance of '{}'".format(self.model.__name__))

        value.validate()


class Email(String):
    """This validator forces fields values to be strings and match a
    valid email address.

    """

    def __init__(self):
        super(Email, self).__init__()

        self.pattern = re.compile('^[^@]+\@[^@]+$')

    @nullable
    def validate(self, value):
        super(Email, self).validate(value)

        if self.pattern.match(value) is None:
            raise errors.ValidationError('should be a valid email')


class URL(String):
    """This validator forces fields values to be strings and match a
    valid URL.

    """

    def __init__(self):
        super(URL, self).__init__()

        # From Django validator:
        #   https://github.com/django/django/blob/master/django/core/validators.py#L47
        self.pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    @nullable
    def validate(self, value):
        super(URL, self).validate(value)

        if self.pattern.match(value) is None:
            raise errors.ValidationError('should be a valid URL')


class IP(String):
    """This validator forces fields values to be strings and match a
    valid IP address.

    """

    def __init__(self):
        super(IP, self).__init__()

        # Regex from:
        #   https://gist.github.com/mnordhoff/2213179
        self.ipv4 = re.compile(r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
        self.ipv6 = re.compile(r'^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)$')

    @nullable
    def validate(self, value):
        super(IP, self).validate(value)

        if self.ipv4.match(value) is None and self.ipv6 is None:
            raise errors.ValidationError('should be a valid IPv4 or IPv6 address')


class URI(String):
    """This validator forces fields values to be strings and match a
    valid URI.

    """

    def __init__(self):
        super(URI, self).__init__()

        self.uri_regex = re.compile(r'([a-z0-9+.-]+)://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

    @nullable
    def validate(self, value):
        super(URI, self).validate(value)

        if self.uri_regex.match(value) is None:
            raise errors.ValidationError('should be a valid URI')
        

class List(Validator):
    """This validator forces field values to be a :keyword:`list`.
    Also a list of inner :mod:`validators` could be specified to validate
    each list element. For example, to validate a list of
    :class:`models.Model` you could do::

        books = fields.Field(validators.List(validators.Model(YourBookModel)))

    :param \*validators: A list of inner validators as possitional arguments.

    """

    def __init__(self, *validators):
        self.validators = validators

    @nullable
    def validate(self, value):
        if not isinstance(value, collections.Sequence):
            raise errors.ValidationError('should be a list')

        for i in value:
            for validator in self.validators:
                validator(i)


class DateTime(Validator):
    @nullable
    def validate(self, value):
        if not isinstance(value, datetime.datetime):
            raise errors.ValidationError('should be a datetime')
