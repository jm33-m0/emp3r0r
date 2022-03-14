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

"""The :mod:`inspection` module provides users and 3rd-party library
developers a public api to access :mod:`booby` objects and classes internal
data, such as defined fields, and some low-level type validations.

This module is based on the Python :py:mod:`inspect` module.

"""

from booby import models


def get_fields(model):
    """Returns a `dict` mapping the given `model` field names to their
    `fields.Field` objects.

    :param model: The `models.Model` subclass or instance you want to
                  get their fields.

    :raises: :py:exc:`TypeError` if the given `model` is not a model.

    """

    if not is_model(model):
        raise TypeError(
            '{} is not a {} subclass or instance'.format(model, models.Model))

    return dict(model._fields)


def is_model(obj):
    """Returns `True` if the given object is a `models.Model` instance
    or subclass. If not then returns `False`.

    """

    try:
        return (isinstance(obj, models.Model) or
                issubclass(obj, models.Model))

    except TypeError:
        return False
