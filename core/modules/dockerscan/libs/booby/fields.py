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

"""The :mod:`fields` module contains a list of `Field` classes
for model's definition.

The example below shows the most common fields and builtin validations::

    class Token(Model):
        key = String()
        secret = String()

    class User(Model):
        login = String(required=True)
        name = String()
        role = String(choices=['admin', 'moderator', 'user'])
        email = Email(required=True)
        token = Embedded(Token, required=True)
        is_active = Boolean(default=False)
"""

import six
import collections

try:
    # Python 3 compatiblity
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from booby import (
    validators as builtin_validators,
    encoders as builtin_encoders,
    decoders as builtin_decoders,
    _utils
)


class Field(object):
    """This is the base class for all :mod:`booby.fields`. This class
    can also be used as field in any :class:`models.Model` declaration.

    :param default: This field `default`'s value.

        If passed a callable object then uses its return value as the
        field's default. This is particularly useful when working with
        `mutable objects <http://effbot.org/zone/default-values.htm>`_.

        If `default` is a callable it can optionaly receive the owner
        `model` instance as its first positional argument.

    :param required: If `True` this field value should not be `None`.
    :param choices: A `list` of values where this field value should be in.
    :param name: Specify an alternate key name to use when decoding and encoding.
    :param read_only: If `True`, the value is treated normally in decoding but omitted during encoding.
    :param \*validators: A list of field :mod:`validators` as positional arguments.

    """

    def __init__(self, *validators, **kwargs):
        self.options = kwargs

        self.default = kwargs.get('default')
        self.description = kwargs.get('description', '')
        self.required = kwargs.get('required', False)
        self.choices = kwargs.get('choices', [])

        assert isinstance(self.choices, list)

        # Setup field validators
        self.validators = []

        if self.required:
            self.validators.append(builtin_validators.Required())

        if self.choices:
            self.validators.append(builtin_validators.In(self.choices))

        self.validators.extend(validators)

    def __repr__(self):
        options = dict(self.options)
        options['validators'] = self.validators

        cls = type(self)

        return '<{}.{}({})>'.format(cls.__module__, cls.__name__,
                                    _utils.repr_options(options))

    def __get__(self, instance, owner):
        if instance is not None:
            try:
                return instance._data[self]
            except KeyError:
                return instance._data.setdefault(self, self._default(instance))

        return self

    def __set__(self, instance, value):
        if not value:
            value = self.default
        instance._data[self] = value

    def _default(self, model):
        if callable(self.default):
            return self.__call_default(model)

        return self.default

    def __call_default(self, *args):
        try:
            return self.default()
        except TypeError as error:
            try:
                return self.default(*args)
            except TypeError:
                raise error

    def validate(self, value):
        for validator in self.validators:
            validator(value)

    def decode(self, value):
        for decoder in self.options.get('decoders', []):
            value = decoder(value)

        return value

    def encode(self, value):
        for encoder in self.options.get('encoders', []):
            value = encoder(value)

        return value

    @property
    def field_type(self):
        """
        :return: Python native type: int, str, float...
        :rtype: object
        """
        raise NotImplemented("This property must be implemented by the subclass")
    

class String(Field):
    """:class:`Field` subclass with builtin `string` validation."""

    def __init__(self, *args, **kwargs):
        super(String, self).__init__(builtin_validators.String(), *args, **kwargs)

    @property
    def field_type(self):
        return six.string_types


class Integer(Field):
    """:class:`Field` subclass with builtin `integer` validation."""

    def __init__(self, *args, **kwargs):
        super(Integer, self).__init__(builtin_validators.Integer(), *args, **kwargs)

    @property
    def field_type(self):
        return six.integer_types


class Float(Field):
    """:class:`Field` subclass with builtin `float` validation."""

    def __init__(self, *args, **kwargs):
        super(Float, self).__init__(builtin_validators.Float(), *args, **kwargs)

    @property
    def field_type(self):
        return float
    

class Boolean(Field):
    """:class:`Field` subclass with builtin `bool` validation."""

    def __init__(self, *args, **kwargs):
        super(Boolean, self).__init__(builtin_validators.Boolean(), *args, **kwargs)

    @property
    def field_type(self):
        return bool
    

class Embedded(Field):
    """:class:`Field` subclass with builtin embedded :class:`models.Model`
    validation.

    """

    def __init__(self, model, *args, **kwargs):
        kwargs.setdefault('encoders', []).append(builtin_encoders.Model())
        kwargs.setdefault('decoders', []).append(builtin_decoders.Model(model))

        super(Embedded, self).__init__(builtin_validators.Model(model), *args, **kwargs)

        self.model = model

    def __set__(self, instance, value):
        if isinstance(value, collections.MutableMapping):
            value = self.model(**value)

        super(Embedded, self).__set__(instance, value)


class Email(String):
    """:class:`Field` subclass with builtin `email` validation."""

    def __init__(self, *args, **kwargs):
        super(Email, self).__init__(builtin_validators.Email(), *args, **kwargs)


class URL(String):
    """:class:`Field` subclass with builtin `URL` validation."""

    def __init__(self, *args, **kwargs):
        super(URL, self).__init__(builtin_validators.URL(), *args, **kwargs)


class IP(String):
    """:class:`Field` subclass with builtin `ip` validation."""

    def __init__(self, *args, **kwargs):
        super(IP, self).__init__(builtin_validators.IP(), *args, **kwargs)


class URI(String):
    """:class:`Field` subclass with builtin `URI` validation."""
    
    def __init__(self, *args, **kwargs):
        super(URI, self).__init__(builtin_validators.URI(), *args, **kwargs)


class Raw(Field):
    """:class:`Field` raw input data"""

    def __init__(self, *args, **kwargs):
        super(Raw, self).__init__(*args, **kwargs)


class List(Field):
    """:class:`Field` subclass with builtin `list` validation
    and default value.

    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('default', [])
        kwargs.setdefault('encoders', []).append(builtin_encoders.List())

        super(List, self).__init__(
            builtin_validators.List(*kwargs.get('inner_validators', [])),
            *args, **kwargs)
    
    @property
    def field_type(self):
        return list


class Collection(Field):
    """:class:`Field` subclass with builtin `list of` :class:`models.Model`
    validation, encoding and decoding.

    Example::

        class Token(Model):
            key = String()
            secret = String()

        class User(Model):
            tokens = Collection(Token)


        user = User({
            'tokens': [
                {
                    'key': 'xxx',
                    'secret': 'yyy'
                },
                {
                    'key': 'zzz',
                    'secret': 'xxx'
                },
            ]
        })

        user.tokens.append(Token(key='yyy', secret='xxx'))

    """

    def __init__(self, model, *args, **kwargs):
        kwargs.setdefault('default', [])

        kwargs.setdefault('encoders', []).append(builtin_encoders.Collection())
        kwargs.setdefault('decoders', []).append(builtin_decoders.Collection(model))
        super(Collection, self).__init__(builtin_validators.List(builtin_validators.Model(model)), *args, **kwargs)
        self.model = model

    def __set__(self, instance, value):
        if isinstance(value, collections.MutableSequence):
            value = self._resolve(value)

        super(Collection, self).__set__(instance, value)

    def _resolve(self, value):
        result = []
        for item in value:
            if isinstance(item, collections.MutableMapping):
                item = self.model(**item)
            result.append(item)
        return result

__all__ = ("Field", "String", "Integer", "Float", "Boolean", "Embedded", "Email", "URL", "List", "Collection", "IP",
           "Raw", "URI")
