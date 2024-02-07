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

from django.db.models import Q
from typing import Optional

from django_woah.utils.q import merge_qs, prefix_q_with_relation, get_object_relation
from .conditions import Condition
from .context import Context
from .enum import PermEnum


class IndirectPerms:
    def __init__(self, **kwargs):
        self.scheme = kwargs.get("scheme")

    def can_receive_perms(self) -> list[PermEnum]:
        """This function is mainly used to avoid unnecessary queries and some infinite recursions."""
        return []

    def get_resources_q(self, context: Context) -> Optional[Q]:
        raise NotImplementedError

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        raise NotImplementedError

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        raise NotImplementedError

    def set_scheme(self, scheme):
        if self.scheme is None:
            self.scheme = scheme


class ConditionalPerms(IndirectPerms):
    def __init__(
        self, conditions: list[Condition], receives_perms: list[PermEnum], **kwargs
    ):
        self.conditions: list[Condition] = conditions
        self.receives_perms: list[PermEnum] = receives_perms

        super().__init__(**kwargs)

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        for condition in self.conditions:
            condition.set_scheme(self.scheme)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [condition.get_resources_q(context) for condition in self.conditions]
        )

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [condition.get_assigned_perms_q(context) for condition in self.conditions],
            connector=Q.OR,
        )

    def can_receive_perms(self):
        return self.receives_perms

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        return all(
            condition.is_authorized_for_unsaved_resource(context)
            for condition in self.conditions
        )

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.conditions} -> {self.receives_perms}"


class TransitiveFromRelationPerms(IndirectPerms):
    def __init__(self, relation: str, restrict_to_perms=None, **kwargs):
        super().__init__(**kwargs)

        self.relation = relation
        self.restrict_to_perms = set(restrict_to_perms or [])

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        self.restrict_to_perms = self.restrict_to_perms.intersection(
            self.scheme.Perms.values()
        )
        self.relation_scheme = self.scheme.get_auth_scheme_by_relation(self.relation)

        if not self.restrict_to_perms:
            self.restrict_to_perms = set(self.scheme.Perms.values())

        relation_scheme_perms = set(self.relation_scheme.get_scheme_perms())

        if not self.restrict_to_perms.issubset(relation_scheme_perms):
            raise ValueError(
                f"{self.relation_scheme} has not borrowed the following perms: {self.restrict_to_perms.difference(relation_scheme_perms)}"
            )

    def get_resources_q(self, context: Context) -> Optional[Q]:
        if context.perm not in self.restrict_to_perms:
            raise ValueError(
                f"{context.perm} not in restrict_to_perms {self.restrict_to_perms}"
            )

        context = context.subcontext(resource=self.relation_scheme.model)

        q = self.relation_scheme.get_resources_q(context)
        if q is None:
            return None

        return prefix_q_with_relation(q, self.relation)

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        return self.relation_scheme.get_assigned_perms_q(
            context=context.subcontext(resource=self.relation_scheme.model)
        )

    def can_receive_perms(self) -> list[PermEnum]:
        return self.restrict_to_perms

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        if context.perm not in self.restrict_to_perms:
            raise ValueError(
                f"{context.perm} not in restrict_to_perms {self.restrict_to_perms}"
            )

        context = context.subcontext(
            resource=get_object_relation(context.resource, self.relation)
        )

        solver = self.scheme.auth_solver

        context.resource = self.scheme.get_auth_scheme_by_relation(self.relation).model
        context.assigned_perms = solver.get_assigned_perms_queryset(context)

        return solver.get_authorized_resources_queryset(context).exists()
