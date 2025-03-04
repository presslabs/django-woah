#  Copyright 2025 Pressinfra SRL
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

from django_woah.models import AssignedPerm, Membership
from .enum import PermEnum
from .knowledge_base import KnowledgeBase


uninitialized = object()

@dataclass
class Context:
    actor: Optional[AbstractUser] = None
    perm: Optional[PermEnum] = None
    resource: Optional[Model | list[Model]] = None
    extra: dict = field(default_factory=dict)

    _assigned_perms: Optional[list[AssignedPerm]] = None
    _memberships: Optional[list[Membership]] = None
    _depth: int = 0
    _knowledge_base: Optional[KnowledgeBase] = None
    _root: Optional[Union["Context", "CombinedContext"]] = None

    def subcontext(self, perm: Optional[PermEnum]=uninitialized, resource=uninitialized):
        if perm is uninitialized:
            perm = self.perm

        if resource is uninitialized:
            resource = self.resource

        return Context(
            actor=self.actor,
            perm=perm,
            resource=resource,
            extra=self.extra,
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

    @property
    def memberships(self):
        if self._memberships is None and self._root:
            return self._root.memberships

        return self._memberships

    @memberships.setter
    def memberships(self, value):
        self._memberships = value

    @property
    def knowledge_base(self):
        if self._knowledge_base is None and self._root:
            return self._root.knowledge_base

        if not self._knowledge_base:
            self._knowledge_base = KnowledgeBase()

        return self._knowledge_base

    @knowledge_base.setter
    def knowledge_base(self, value):
        self._knowledge_base = value


@dataclass
class CombinedContext:
    contexts: list[Context] = field(default_factory=list)
    assigned_perms: Optional[list[AssignedPerm]] = None
    memberships: Optional[list[Membership]] = None
    knowledge_base: KnowledgeBase = field(default_factory=KnowledgeBase)

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

            if isinstance(resource, Model):
                if not isinstance(context.resource, resource.__class__):
                    raise ValueError("If contexts use different resources, they must be of same Model.")
