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

from django.db.models import Q, Model
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

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        raise NotImplementedError

    def verify_authorization(self, context: Context) -> bool:
        raise NotImplementedError

    def set_scheme(self, scheme):
        if self.scheme is None:
            self.scheme = scheme


class ConditionalPerms(IndirectPerms):
    def __init__(self, conditions: list[Condition], receives_perms: list[PermEnum], **kwargs):
        self.conditions: list[Condition] = conditions
        self.receives_perms: list[PermEnum] = receives_perms

        super().__init__(**kwargs)

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        for condition in self.conditions:
            condition.set_scheme(self.scheme)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        return merge_qs([condition.get_resources_q(context) for condition in self.conditions])

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [condition.get_assigned_perms_q(context) for condition in self.conditions],
            connector=Q.OR,
        )

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [condition.get_memberships_q(context) for condition in self.conditions],
            connector=Q.OR,
        )

    def can_receive_perms(self):
        return self.receives_perms

    def verify_authorization(self, context: Context) -> bool:
        for condition in self.conditions:
            if (known := self.scheme._check_knowledgebase(context, condition)) is not None:
                result = known
            else:
                result = condition.verify_authorization(context)
                self.scheme._add_to_knowledgebase(context, condition, truth=result)

            if not result:
                return False

        return True

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.conditions} -> {self.receives_perms}"


class TransitiveFromRelationPerms(IndirectPerms):
    def __init__(self, relation: str, restrict_to_perms=None, **kwargs):
        super().__init__(**kwargs)

        self.relation = relation
        self.restrict_to_perms = set(restrict_to_perms or [])

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        if not self.restrict_to_perms:
            self.restrict_to_perms = set(self.scheme.get_scheme_perms())
        else:
            self.restrict_to_perms = self.restrict_to_perms.intersection(self.scheme.get_scheme_perms())

        self.relation_scheme = self.scheme.get_auth_scheme_by_relation(self.relation)

        relation_scheme_perms = set(self.relation_scheme.get_scheme_perms())

        if not self.restrict_to_perms.issubset(relation_scheme_perms):
            raise ValueError(
                f"{self.relation_scheme} has not borrowed the following perms: {self.restrict_to_perms.difference(relation_scheme_perms)}"
            )

    def get_resources_q(self, context: Context) -> Optional[Q]:
        if context.perm not in self.restrict_to_perms:
            raise ValueError(f"{context.perm} not in restrict_to_perms {self.restrict_to_perms}")

        context = context.subcontext(resource=self.relation_scheme.model)

        q = self.relation_scheme.get_resources_q(context)
        if q is None:
            return None

        return prefix_q_with_relation(q, self.relation)

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        relation_resource = self.relation_scheme.model

        if isinstance(context.resource, self.scheme.model):
            concrete_relation_resource = get_object_relation(context.resource, self.relation)
            if concrete_relation_resource is None:
                return None

            if isinstance(concrete_relation_resource, Model):
                relation_resource = concrete_relation_resource

        return self.relation_scheme.get_assigned_perms_q(
            context=context.subcontext(resource=relation_resource)
        )

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        relation_resource = self.relation_scheme.model

        if isinstance(context.resource, self.scheme.model):
            concrete_relation_resource = get_object_relation(context.resource, self.relation)
            if concrete_relation_resource is None:
                return None

            if isinstance(concrete_relation_resource, Model):
                relation_resource = concrete_relation_resource

        return self.relation_scheme.get_memberships_q(
            context=context.subcontext(resource=relation_resource)
        )

    def can_receive_perms(self) -> list[PermEnum]:
        return self.restrict_to_perms

    def verify_authorization(self, context: Context) -> bool:
        if context.perm not in self.restrict_to_perms:
            raise ValueError(f"{context.perm} not in restrict_to_perms {self.restrict_to_perms}")

        resource = get_object_relation(context.resource, self.relation)
        if resource is None:
            return False

        context = context.subcontext(resource=get_object_relation(context.resource, self.relation))

        # TODO: check if we (always) have to fetch new assigned_perms or they're being fetched already

        if context.resource.pk:
            return self.relation_scheme.verify_authorization(context)

        solver = self.scheme.auth_solver
        context.assigned_perms = solver.get_assigned_perms_queryset(context)

        return solver.get_resources_queryset(context).exists()
