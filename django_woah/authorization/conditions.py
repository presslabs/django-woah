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

import enum
from django.db.models import Q
from functools import reduce
from typing import Optional, Callable

from django_woah.models import UserGroup
from django_woah.utils.q import (
    get_object_relation,
    merge_qs,
    prefix_q_with_relation,
    verify_resource_by_q,
)
from .context import Context
from .enum import PermEnum


class Condition:
    def __init__(self, **kwargs):
        self.scheme = kwargs.get("scheme")

    def get_resources_q(self, context: Context) -> Optional[Q]:
        raise NotImplementedError

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        return None

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        return False

    def set_scheme(self, scheme):
        if self.scheme is None:
            self.scheme = scheme

    def __and__(self, other):
        return CombinedCondition(
            self, other, operation=CombinedCondition.OPERATIONS.AND
        )

    def __or__(self, other):
        return CombinedCondition(self, other, operation=CombinedCondition.OPERATIONS.OR)


class CombinedCondition(Condition):
    class OPERATIONS(enum.StrEnum):
        AND = "and"
        OR = "or"

    def __init__(self, *conditions: Condition, operation: OPERATIONS, **kwargs):
        self.conditions = conditions
        self.operation = operation

        super().__init__(**kwargs)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        result = Q()

        for condition in self.conditions:
            q = condition.get_resources_q(context)

            if self.operation == self.OPERATIONS.AND:
                if q is None:
                    return None

                result &= q
            elif self.operation == self.OPERATIONS.OR:
                if q is not None:
                    result |= q
            else:
                raise ValueError("Unexpected Condition operation")

        return result

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        qs = [
            q
            for condition in self.conditions
            if (q := condition.get_assigned_perms_q(context)) is not None
        ]

        if not qs:
            return None

        return reduce(
            lambda q1, q2: q1 | q2,
            qs,
        )

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        if not self.conditions:
            return True

        for condition in self.conditions:
            ok = condition.is_authorized_for_unsaved_resource(context)

            if self.operation == self.OPERATIONS.AND:
                if not ok:
                    return False
            elif self.operation == self.OPERATIONS.OR:
                if ok:
                    return True
            else:
                raise ValueError("Unexpected Condition operation")

        return self.operation == self.OPERATIONS.AND

    def set_scheme(self, scheme):
        if self.scheme is None:
            self.scheme = scheme

        for condition in self.conditions:
            condition.set_scheme(self.scheme)


class BaseOwnerCondition(Condition):
    def __init__(self, actor, **kwargs):
        super().__init__(**kwargs)

        self.actor = actor

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        relation_model = (
            self.scheme.model
            if self.scheme.owner_relation == "*"
            else self.scheme.get_model_for_relation(self.scheme.owner_relation)
        )
        self.relation_is_user_group = relation_model == UserGroup
        self.relation = self.scheme.owner_relation
        self.account_owner_relation = (
            self.relation
            if not self.relation_is_user_group
            else (f"{self.relation}__owner" if not self.relation == "*" else "owner")
        )


class HasRootMembership(BaseOwnerCondition):
    def __init__(self, actor, is_outside_collaborator=None, **kwargs):
        super().__init__(actor=actor, **kwargs)

        self.is_outside_collaborator = is_outside_collaborator

    def get_resources_q(self, _: Context) -> Q:
        user_groups_relation = (
            "owned_user_groups__" if not self.relation_is_user_group else ""
        )
        relation = "" if self.relation == "*" else f"{self.relation}__"

        query = {
            f"{relation}{user_groups_relation}memberships__user": self.actor,
            f"{relation}{user_groups_relation}kind": "root",
        }
        if self.is_outside_collaborator is not None:
            query[
                f"{relation}{user_groups_relation}memberships__is_outside_collaborator"
            ] = self.is_outside_collaborator

        return Q(**query)

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        resource = context.resource

        owner = get_object_relation(resource, self.relation)

        if not self.relation_is_user_group:
            owner = owner.owned_user_groups.get(kind="root")

        if isinstance(owner, UserGroup):
            if not owner.kind == "root":
                return False

        query = {"user": self.actor}

        if self.is_outside_collaborator is not None:
            query["is_outside_collaborator"] = self.is_outside_collaborator

        return owner.memberships.filter(**query).exists()


class HasSameResourcePerms(Condition):
    def __init__(self, perms: list[PermEnum], **kwargs):
        super().__init__(**kwargs)

        self.perms = perms

    def get_resources_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [
                self.scheme.get_resources_q(context.subcontext(perm))
                for perm in self.perms
            ]
        )

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [
                self.scheme.get_assigned_perms_q(context.subcontext(perm))
                for perm in self.perms
            ],
            connector=Q.OR,
        )

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        solver = self.scheme.auth_solver

        return all(
            solver.is_authorized_for_unsaved_resource(context.subcontext(perm))
            for perm in self.perms
        )

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.scheme.model} < {self.perms}"


class HasRelatedResourcePerms(Condition):
    def __init__(
        self,
        relation: str,
        perms: list[PermEnum],
        unsaved_object_relation=None,
        **kwargs,
    ):
        if not isinstance(perms, (list, set, tuple)):
            raise ValueError(f"Received perms of type {type(perms)}: {perms}")

        self.perms = perms
        self.relation = relation
        # The "unsaved_object_relation" parameter may be used when dealing with GenericForeignKey relations, because
        # Django doesn't allow assigning to the reverse of a GenericRelation even if that basically means assigning
        # to the GenericForeignKey (the GenericRelation doesn't exist in the DB anyway).
        # For example for "relation" you should set the GenericRelation.related_query_name, but for
        # "unsaved_object_relation" you should set the GenericForeignKey field name (usually "content_object")
        self.unsaved_object_relation = unsaved_object_relation or self.relation

        super().__init__(**kwargs)

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        # TODO: Check if relation actually exists on the scheme's Model.
        try:
            self.related_scheme = self.scheme.get_auth_scheme_by_relation(self.relation)
        except ValueError:
            # TODO: only catch this when the relation is generic, because most of the times the ValueError exc is valid
            #  and should raise
            self.related_scheme = self.scheme.auth_solver.get_auth_scheme_for_model(
                self.perms[0].auth_scheme.model
            )

    def get_resources_q(self, context: Context) -> Optional[Q]:
        qs = [
            prefix_q_with_relation(q, self.relation)
            for perm in self.perms
            if (
                (
                    q := self.related_scheme.get_resources_q(
                        context.subcontext(
                            perm=perm, resource=self.related_scheme.model
                        )
                    )
                )
                is not None
            )
        ]

        if not qs:
            return None

        return reduce(lambda q1, q2: q1 & q2, qs)

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        qs = [
            q
            for perm in self.perms
            if (
                q := self.related_scheme.get_assigned_perms_q(
                    context.subcontext(perm=perm, resource=self.related_scheme.model)
                )
            )
            is not None
        ]
        if not qs:
            return None

        return reduce(
            lambda q1, q2: q1 | q2,
            qs,
        )

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        resource = get_object_relation(context.resource, self.unsaved_object_relation)

        solver = self.scheme.auth_solver
        #
        # context.resource = self.scheme.get_auth_scheme_by_relation(
        #     self.relation
        # ).model
        # context.assigned_perms = solver.get_assigned_perms_queryset(context)

        # TODO: filter(pk=context.resource.pk). should be enforced by the solver; remove from here when implemented
        return all(
            solver.get_authorized_resources_queryset(context.subcontext(perm, resource))
            .filter(pk=resource.pk)
            .exists()
            for perm in self.perms
        )

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.scheme.model}.{self.relation} < {self.perms}"


class HasUnrelatedResourcePerms(Condition):
    def __init__(self, resource, perms: list[PermEnum], **kwargs):
        if not isinstance(perms, (list, set, tuple)):
            raise ValueError(f"Received perms of type {type(perms)}: {perms}")

        self.resource = resource

        self.perms = perms

        super().__init__(**kwargs)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        solver = self.scheme.auth_solver

        if all(
            self.resource
            in solver.get_authorized_resources_queryset(
                context.subcontext(perm, self.resource)
            )
            for perm in self.perms
        ):
            return Q()

        return None

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        solver = self.scheme.auth_solver

        qs = [
            q
            for perm in self.perms
            if (
                q := solver.get_assigned_perms_q(
                    context.subcontext(perm, self.resource)
                )
            )
            is not None
        ]
        if not qs:
            return None

        return reduce(
            lambda q1, q2: q1 | q2,
            qs,
        )

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        # TODO: Implement
        return self.get_resources_q(context) == Q()

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.resource} < {self.perms}"


class QCondition(Condition):
    def __init__(
        self, q: Q, authorize_unsaved_resource_func: Optional[Callable] = None, **kwargs
    ):
        self.q = q
        self.authorize_unsaved_resource_func = authorize_unsaved_resource_func

        super().__init__(**kwargs)

    def get_resources_q(self, _: Context) -> Q:
        return self.q

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        if self.authorize_unsaved_resource_func:
            return self.authorize_unsaved_resource_func(context)

        return verify_resource_by_q(context.resource, self.q)

    def __repr__(self):
        return self.q.__repr__()
