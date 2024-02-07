#  Copyright 2024 Pressinfra SRL
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from dataclasses import dataclass, field
from django.contrib.auth.models import AbstractUser
from django.db.models import Model
from typing import Optional, Union

from django_woah.models import AssignedPerm
from .enum import PermEnum


@dataclass
class Context:
    actor: Optional[AbstractUser] = None
    perm: Optional[PermEnum] = None
    resource: Optional[Model | list[Model]] = None
    extra: dict = field(default_factory=dict)

    _assigned_perms: Optional[list[AssignedPerm]] = None
    _depth: int = 0
    _root: Optional[Union["Context", "CombinedContext"]] = None

    def subcontext(self, perm=None, resource=None):
        return Context(
            actor=self.actor,
            perm=perm or self.perm,
            resource=resource or self.resource,
            extra=self.extra,
            # _assigned_perms=self.assigned_perms,
            _depth=self._depth,
            _root=self._root or self,
        )

    @property
    def assigned_perms(self):
        if self._assigned_perms is None and self._root:
            return self._root.assigned_perms

        return self._assigned_perms

    @assigned_perms.setter
    def assigned_perms(self, value):
        self._assigned_perms = value


@dataclass
class CombinedContext:
    contexts: list[Context] = field(default_factory=list)
    assigned_perms: Optional[list[AssignedPerm]] = None

    def __post_init__(self):
        self.validate()

    def add(self, context: Context):
        if not context._root:
            context._root = self

        self.contexts.append(context)
        self.validate()

    def validate(self):
        if not self.contexts:
            return

        actor = self.contexts[0].actor
        resource = self.contexts[0].resource

        for context in self.contexts[1:]:
            if context.actor != actor:
                raise ValueError("Cannot have contexts with different actors.")

            if context.resource != resource:
                raise ValueError("Cannot have contexts with different resources.")
