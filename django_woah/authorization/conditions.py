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

from __future__ import annotations
import enum
import time

from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.db.models import Q, Field, Model, QuerySet
from functools import reduce
from typing import Optional, Callable, TYPE_CHECKING

from django_woah.models import UserGroup
from django_woah.utils.q import (
    get_object_relation,
    merge_qs,
    prefix_q_with_relation,
    verify_resource_by_q,
)
from .context import Context
from .enum import PermEnum
from .knowledge_base import Atom

if TYPE_CHECKING:
    from .indirect_perms import ConditionalPerms


class Condition:
    def __init__(self, **kwargs):
        self.scheme = kwargs.get("scheme")

    @property
    def _identity(self) -> tuple:
        return (f"{_class_fq(self.__class__)}",)

    def _get_atoms(self, context):
        return Atom((context.actor, None, _resource_to_atom(context.resource)) + self._identity)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        raise NotImplementedError

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        return None

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        return None

    def verify_authorization(self, context: Context) -> bool:
        return False

    def set_scheme(self, scheme):
        if self.scheme is None:
            self.scheme = scheme

    def __and__(self, other):
        return CombinedCondition(self, other, operation=CombinedCondition.OPERATIONS.AND)

    def __or__(self, other):
        return CombinedCondition(self, other, operation=CombinedCondition.OPERATIONS.OR)

    def __rshift__(self, other: list[PermEnum]) -> "ConditionalPerms":
        from .indirect_perms import ConditionalPerms

        return ConditionalPerms(conditions=[self], receives_perms=other)

    # def __getattribute__(self, item):
    #     def wrapper(func):
    #         def debug(*args, **kwargs):
    #             start_time = time.time()
    #             result = func(*args, **kwargs)
    #             end_time = time.time()
    #
    #             print("[DEBUG]", f"{'%.4f' % (end_time-start_time)}s", f"{self.__class__.__name__}.{func.__name__}", result)
    #             return result
    #
    #         return debug
    #
    #     if item in ["verify_authorization"]:
    #         return wrapper(super().__getattribute__(item))
    #
    #     return super().__getattribute__(item)


class CombinedCondition(Condition):
    class OPERATIONS(enum.StrEnum):
        AND = "and"
        OR = "or"

    def __init__(self, *conditions: Condition, operation: OPERATIONS, **kwargs):
        self.conditions = conditions
        self.operation = operation

        super().__init__(**kwargs)

    @property
    def _identity(self) -> tuple:
        return super()._identity + (self.operation, *(sorted(condition._identity for condition in self.conditions)))

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

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        qs = [
            q
            for condition in self.conditions
            if (q := condition.get_memberships_q(context)) is not None
        ]

        if not qs:
            return None

        return reduce(
            lambda q1, q2: q1 | q2,
            qs,
        )

    def verify_authorization(self, context: Context) -> bool:
        if not self.conditions:
            return True

        for condition in self.conditions:
            ok = condition.verify_authorization(context)

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

    def __repr__(self):
        operator = "&" if self.operation == "and" else "|"
        return f" {operator} ".join(c.__repr__() for c in self.conditions)


class BaseOwnerCondition(Condition):
    def __init__(self, actor, **kwargs):
        super().__init__(**kwargs)

        self.actor = actor

    @property
    def _identity(self) -> tuple:
        return super()._identity + (self.actor,)

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        self.relation_model = (
            self.scheme.model
            if self.scheme.owner_relation == "*"
            else self.scheme.get_model_for_relation(self.scheme.owner_relation)
        )
        self.relation_is_user_group = self.relation_model == UserGroup
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

    @property
    def _identity(self) -> tuple:
        return super()._identity + (self.is_outside_collaborator,)

    def get_memberships_q(self, context: Context) -> Q:
        if isinstance(context.resource, Model):
            owner = get_object_relation(context.resource, self.relation)

            q = Q(user_group=owner) if self.relation_is_user_group else Q(user_group__owner=owner)
        else:
            # else we assume context.resource is a Model class and there's no point in filtering for the owner
            q = Q(user_group__kind=UserGroup.KINDS.ROOT)

        q &= Q(user=context.actor)

        if self.is_outside_collaborator is not None:
            q &= Q(is_outside_collaborator=self.is_outside_collaborator)

        return q


    def get_resources_q(self, context: Context) -> Q:
        user_groups_relation = "owned_user_groups__" if not self.relation_is_user_group else ""
        relation = "" if self.relation == "*" else f"{self.relation}__"

        if isinstance(context.memberships, list) or (
            isinstance(context.memberships, QuerySet) and context.memberships._result_cache is not None
        ):
            user_groups = []

            for membership in context.memberships:
                if self.is_outside_collaborator is not None and self.is_outside_collaborator != membership.is_outside_collaborator:
                    continue

                if membership.user_id == context.actor.pk and membership.user_group.kind == "root":
                    user_groups.append(membership.user_group)

            return Q(**{f"{relation}{user_groups_relation}in": user_groups})

        query = {
            f"{relation}{user_groups_relation}memberships__user": self.actor,
            f"{relation}{user_groups_relation}kind": "root",
        }
        if self.is_outside_collaborator is not None:
            query[f"{relation}{user_groups_relation}memberships__is_outside_collaborator"] = (
                self.is_outside_collaborator
            )

        return Q(**query)

    def _get_owner(self, resource):
        try:
            return get_object_relation(resource, self.relation)
        except ObjectDoesNotExist:
            return None
        except AttributeError as exception:
            if str(exception).startswith("'NoneType' object has no attribute"):
                return None

            raise  # TODO: Decide if reraise is good here
        except ValueError as exception:
            if str(exception).endswith("before this many-to-many relationship can be used."):
                return None

            raise

    def verify_authorization(self, context: Context) -> bool:
        resource = context.resource
        owner = self._get_owner(resource)

        if not owner:
            return False

        if isinstance(owner, UserGroup):
            if not owner.kind == "root":
                return False

        # Check for saved/prefetched resource
        if context.resource.pk:
            for membership in context.memberships:
                # Although outside collaborator is handled in get_membership_q, those might be retrieved from other
                # conditions, and so we still need to check...
                if self.is_outside_collaborator is not None:
                    if membership.is_outside_collaborator != self.is_outside_collaborator:
                        continue

                if isinstance(owner, UserGroup):
                    if membership.user_group == owner:
                        return True
                else:
                    if membership.user_group.owner_id == owner.pk and membership.user_group.kind == "root":
                        return True

            return False

        # Check for unsaved resource
        # TODO: see if the logic for saved/prefetched resource could/should substitute this one
        query = {"user": self.actor}

        if self.is_outside_collaborator is not None:
            query["is_outside_collaborator"] = self.is_outside_collaborator

        return owner.memberships.filter(**query).exists()


class HasSameResourcePerms(Condition):
    def __init__(self, perms: list[PermEnum], **kwargs):
        super().__init__(**kwargs)

        self.perms = perms

    @property
    def _identity(self) -> tuple:
        # TODO: how to handle side-effects (aka combinations of self.perms)
        return super()._identity + (*self.perms,)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [self.scheme.get_resources_q(context.subcontext(perm)) for perm in self.perms]
        )

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        return merge_qs(
            [self.scheme.get_assigned_perms_q(context.subcontext(perm)) for perm in self.perms],
            connector=Q.OR,
        )

    def verify_authorization(self, context: Context) -> bool:
        # TODO: old `is_authorized_for_unsaved_resource` used `self.scheme.auth_solver` instead; check if it was necessary
        for perm in self.perms:
            if not self.scheme.verify_authorization(context.subcontext(perm)):
                return False

        return True

    def __repr__(self):
        model = self.scheme.model if self.scheme else None
        return f"{self.__class__.__name__}: {model} < {self.perms}"


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
        self.field: Field

        super().__init__(**kwargs)

    @property
    def _identity(self) -> tuple:
        # TODO: decide what to do with self.relation and self.unsaved_object_relation
        #       maybe merge identity and get_atom to always have the context and decide based on that

        return super()._identity + (self.relation, self.unsaved_object_relation, *self.perms)

    def set_scheme(self, scheme):
        super().set_scheme(scheme)

        try:
            self.related_scheme = self.scheme.get_auth_scheme_by_relation(self.relation)
        except ValueError:
            # TODO: only catch this when the relation is generic, because most of the times the ValueError exc is valid
            #  and should raise
            model = self.perms[0].auth_scheme.model
            self.related_scheme = self.scheme.auth_solver.get_auth_scheme_for_model(model)

        # TODO: check the relationship all the way, not just the first field
        model = self.scheme.model
        field_name = self.relation.split("__", 1)[0]

        try:
            self.field = model._meta.get_field(field_name)
        except FieldDoesNotExist:
            raise AttributeError(
                f"{field_name} was specified in {self.__class__} 'owner_relation', but doesn't exist on {model}"
            )

    def get_resources_q(self, context: Context) -> Optional[Q]:
        qs = [
            prefix_q_with_relation(q, self.relation)
            for perm in self.perms
            if (
                (
                    q := self.related_scheme.get_resources_q(
                        context.subcontext(perm=perm, resource=self.related_scheme.model)
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

    def verify_authorization(self, context: Context) -> bool:
        relation = self.relation if context.resource.pk else self.unsaved_object_relation

        resource = get_object_relation(context.resource, relation)

        if not resource:
            return False

        if not resource.pk or len(self.perms) == 1:
            # TODO: is this even a possible case and does it make sense to call verify_authorization instead of querying
            #       performance-wise?
            for perm in self.perms:
                if not self.related_scheme.verify_authorization(context.subcontext(perm, resource)):
                    return False

            return True

        solver = self.scheme.auth_solver
        #
        # context.resource = self.scheme.get_auth_scheme_by_relation(
        #     self.relation
        # ).model
        # context.assigned_perms = solver.get_assigned_perms_queryset(context)

        # TODO: filter(pk=context.resource.pk). should be enforced by the solver; remove from here when implemented
        # TODO: Optimize below into a single queryset that uses filter(pk=self.resource.pk).exists()
        for perm in self.perms:
            if not solver.get_resources_queryset(context.subcontext(perm, resource)).filter(pk=resource.pk).exists():
                return False

        return True

    def __repr__(self):
        model = self.scheme.model if self.scheme else None

        return f"{self.__class__.__name__}: {model}.{self.relation} < {self.perms}"


class HasUnrelatedResourcePerms(Condition):
    def __init__(self, resource, perms: list[PermEnum], **kwargs):
        if not isinstance(perms, (list, set, tuple)):
            raise ValueError(f"Received perms of type {type(perms)}: {perms}")

        self.resource = resource
        self.perms = perms

        super().__init__(**kwargs)

    @property
    def _identity(self) -> tuple:
        return super()._identity + (self.resource, *self.perms)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        if not isinstance(self.resource, Model) and not self.resource.pk:
            # Sometimes self.resource will be a Model class instead of an instance
            # TODO: Also we expect the resource to already be saved, but maybe we could handle the unsaved resource case
            return None

        solver = self.scheme.auth_solver

        # TODO: Optimize below into a single queryset that uses filter(pk=self.resource.pk).exists()
        for perm in self.perms:
            if not solver.get_resources_queryset(context.subcontext(perm, self.resource)).filter(pk=self.resource.pk).exists():
                return None

        return Q()

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        solver = self.scheme.auth_solver

        qs = [
            q
            for perm in self.perms
            if (q := solver.get_assigned_perms_q(context.subcontext(perm, self.resource)))
            is not None
        ]
        if not qs:
            return None

        return reduce(
            lambda q1, q2: q1 | q2,
            qs,
        )

    def verify_authorization(self, context: Context) -> bool:
        related_scheme = self.scheme.auth_solver.get_auth_scheme_for_model(self.resource.__class__)

        if self.resource.pk:
            for perm in self.perms:
                if not related_scheme.verify_authorization(context.subcontext(perm, self.resource)):
                    return False

            return True

        # TODO: Implement
        return self.get_resources_q(context) == Q()

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.resource} < {self.perms}"


class QCondition(Condition):
    def __init__(self, q: Q, verify_for_unsaved_resource_func: Optional[Callable] = None, **kwargs):
        self.q = q
        self.verify_for_unsaved_resource_func = verify_for_unsaved_resource_func

        super().__init__(**kwargs)

    @property
    def _identity(self) -> tuple:
        # TODO: decide what to do about self.q and self.verify_for_unsaved_resource_func, aka saved/unsaved resource
        return super()._identity + (self.q, self.verify_for_unsaved_resource_func)

    def get_resources_q(self, _: Context) -> Q:
        return self.q

    def verify_authorization(self, context: Context) -> bool:
        if not context.resource.pk and self.verify_for_unsaved_resource_func:
            return self.verify_for_unsaved_resource_func(context)

        return verify_resource_by_q(context.resource, self.q)

    def __repr__(self):
        return self.q.__repr__()


def _class_fq(klass):
    return f"{klass.__module__}.{klass.__qualname__}"


def _resource_to_atom(resource):
    if isinstance(resource, type):
        print("Unexpected class instead of resource")
        return (_class_fq(resource),)

    return (_class_fq(resource.__class__), resource.pk)
