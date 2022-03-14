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

"""The `models` module contains the `booby` highest level abstraction:
the `Model`.

To define a model you should subclass the :class:`Model` class and
add a list of :mod:`fields` as attributes. And then you could instantiate
your `Model` and work with these objects.

Something like this::

    class Repo(Model):
         name = fields.String()
         owner = fields.Embedded(User)

    booby = Repo(
        name='Booby',
        owner={
            'login': 'jaimegildesagredo',
            'name': 'Jaime Gil de Sagredo'
        })

    print booby.to_json()
    '{"owner": {"login": "jaimegildesagredo", "name": "Jaime Gil de Sagredo"}, "name": "Booby"}'
"""

import six
import collections
try:
    import ujson as json
except ImportError:
    import json


from booby import mixins, fields, errors, _utils


class ModelMeta(type):
    def __new__(cls, name, bases, attrs):
        attrs['_fields'] = {}

        for base in bases:
            if hasattr(base, '_fields'):
                for k, v in base._fields.items():
                    attrs['_fields'][k] = v
            for k, v in base.__dict__.items():
                if isinstance(v, fields.Field):
                    attrs['_fields'][k] = v

        for k, v in attrs.items():
            if isinstance(v, fields.Field):
                attrs['_fields'][k] = v

        return super(ModelMeta, cls).__new__(cls, name, bases, attrs)

    def __repr__(cls):
        return '<{}.{}({})>'.format(cls.__module__, cls.__name__,
                                    _utils.repr_options(cls._fields))


@six.add_metaclass(ModelMeta)
class Model(mixins.Encoder):
    """The `Model` class. All Booby models should subclass this.

    By default the `Model's` :func:`__init__` takes a list of keyword arguments
    to initialize the `fields` values. If any of these keys is not a `field`
    then raises :class:`errors.FieldError`. Of course you can overwrite the
    `Model's` :func:`__init__` to get a custom behavior.

    You can get or set Model `fields` values in two different ways: through
    object attributes or dict-like items::

        >>> booby.name is booby['name']
        True
        >>> booby['name'] = 'booby'
        >>> booby['foo'] = 'bar'
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
        errors.FieldError: foo

    :param \*\*kwargs: Keyword arguments with the fields values to initialize the model.

    """

    def __new__(cls, *args, **kwargs):
        model = super(Model, cls).__new__(cls)
        model._data = {}
        model.ignore_missing = bool(getattr(model, "__ignore_missing__", False))

        return model

    def __init__(self, **kwargs):
        self._update(kwargs)

    def __repr__(self):
        cls = type(self)

        return '<{}.{}({})>'.format(cls.__module__, cls.__name__,
                                    _utils.repr_options(dict(self)))

    def __iter__(self):
        for name in self._fields:
            value = getattr(self, name)

            if isinstance(value, Model):
                value = dict(value)
            elif isinstance(value, collections.MutableSequence):
                value = self._encode_sequence(value)

            yield name, value

    def _encode_sequence(self, sequence):
        result = []

        for value in sequence:
            if isinstance(value, Model):
                value = dict(value)

            result.append(value)

        return result

    def __getitem__(self, k):
        if k not in self._fields:
            raise errors.FieldError(k)

        return getattr(self, k)

    def __setitem__(self, k, v):
        if k not in self._fields:
            raise errors.FieldError(k)

        setattr(self, k, v)

    def update(self, *args, **kwargs):
        """This method updates the `model` fields values with the given `dict`.
        The model can be updated passing a dict object or keyword arguments,
        like the Python's builtin :py:func:`dict.update`.

        """

        self._update(dict(*args, **kwargs))

    def _update(self, values):
        for k, v in values.items():
            self[k] = v

    @property
    def is_valid(self):
        """This property will be `True` if there are not validation
        errors in this `model` fields. If there are any error then
        will be `False`.

        This property wraps the :func:`Model.validate` method to be
        used in a boolean context.

        """

        try:
            self.validate()
        except errors.ValidationError:
            return False
        else:
            return True

    @property
    def descriptions(self):
        """This property returns a dict of strings with the name of propery as a key
        and their description as a value"""

        res = {}
        for name, field in list(self._fields.items()):
            res[name] = field.description
        return res

    def description(self, key):
        try:
            return self._fields[key].description
        except KeyError:
            return None
            
    def validate(self):
        """This method validates the entire `model`. That is, validates
        all the :mod:`fields` within this model.

        If some `field` validation fails, then this method raises the same
        exception that the :func:`field.validate` method had raised, but
        with the field name prepended.

        """

        for name, field in self._fields.items():
            try:
                field.validate(getattr(self, name))
            except errors.ValidationError as err:
                raise errors.ValidationError('%s %s' % (name, err))

    @property
    def validation_errors(self):
        """Generator of field name and validation error string pairs
        for each validation error on this `model` fields.

        """

        for name, field in self._fields.items():
            try:
                field.validate(getattr(self, name))
            except errors.ValidationError as err:
                yield name, str(err)

    def to_json(self, *args, **kwargs):
        """This method returns the `model` as a `json string`. It receives
        the same arguments as the builtin :py:func:`json.dump` function.

        To build a json representation of this `model` this method iterates
        over the object to build a `dict` and then serializes it as json.

        """

        return json.dumps(dict(self), *args, **kwargs)

    @classmethod
    def decode(self, raw):
        result = {}

        for name, field in self._fields.items():
            try:
                value = raw[field.options.get('name', name)]
            except KeyError:
                continue
            else:
                value = field.decode(value)

            result[name] = value

        return result

    @classmethod
    def properties(cls):
        """Get properties defined in Model without instantiate them"""
        if hasattr(cls, "_fields"):
            return cls._fields
        else:
            ret = {}
            for k, v in six.iteritems(cls.__dict__):
                if k.startswith("_"):
                    continue
            
                ret[k] = v
    
        return ret
    
__all__ = ("Model", )

