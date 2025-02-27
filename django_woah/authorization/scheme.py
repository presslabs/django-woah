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

from functools import reduce
from typing import Optional
from typing import TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q, Model

from django_woah.models import AssignedPerm, Membership
from django_woah.utils.q import merge_qs, prefix_q_with_relation, pop_parts_of_q

if TYPE_CHECKING:
    from .solver import AuthorizationSolver

from .conditions import Condition
from .context import Context
from .enum import PermEnum
from .indirect_perms import IndirectPerms


class AuthorizationScheme:
    pass


class ModelAuthorizationScheme(AuthorizationScheme):
    owner_relation: str
    model: type[Model]
    Perms: PermEnum
    Roles: PermEnum
    allow_directly_assigned_perms = True

    def __init__(self):
        auth_solver: "AuthorizationSolver"  # noqa: F842

    def __init_subclass__(cls, **kwargs):
        for value in getattr(cls, "Perms", []):
            value.auth_scheme = cls
            value.is_permission = True
            value.is_role = False

        for value in getattr(cls, "Roles", None) or []:
            value.auth_scheme = cls
            value.is_permission = False
            value.is_role = True

    @classmethod
    def get_borrowed_perms(cls) -> list[PermEnum]:
        """
        Used to specify what perms of other schemes can be applied to this scheme.
        Necessary for when using TransitiveFromRelationPerms for example.
        """
        return []

    @classmethod
    def get_scheme_perms(cls, exclude_borrowed=False) -> list[PermEnum]:
        perms_and_roles = [] if exclude_borrowed else cls.get_borrowed_perms()

        if roles := getattr(cls, "Roles", []):
            perms_and_roles = list(roles) + perms_and_roles

        if perms := getattr(cls, "Perms", []):
            perms_and_roles = list(perms) + perms_and_roles

        return perms_and_roles

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return []

    def get_scheme_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        indirect_perms = []
        for indirect_perm in self.get_indirect_perms(context):
            indirect_perm.set_scheme(self)
            indirect_perms.append(indirect_perm)

        return indirect_perms

    def get_implicit_conditions(self, context: Context) -> list[Condition]:
        return []

    def get_scheme_implicit_conditions(self, context: Context) -> list[Condition]:
        implicit_conditions = []
        for implicit_condition in self.get_implicit_conditions(context):
            implicit_condition.set_scheme(self)
            implicit_conditions.append(implicit_condition)

        return implicit_conditions

    def get_resources_q_from_directly_assigned_perms(
        self, context: Context
    ) -> Optional[Q]:
        # TODO:
        #  For when specific instances of models are queried, relying on assigned_perms
        #  to tell the truth here might cascade upstream in unexpected ways.
        #  So maybe using Context here as well and considering context.resource.pks, or somehow
        #  restricting to certain PKs could be the solution.

        if not self.allow_directly_assigned_perms:
            return None

        owner_based_q = None

        if hasattr(self, "owner_relation"):
            relation_model = self.get_model_for_relation(self.owner_relation)

            owner_based_matches = [
                assigned_perm.owner_id  # if relation_model != UserGroup else a.root_id
                for assigned_perm in context.assigned_perms
                if (
                    assigned_perm.perm == context.perm
                    and not assigned_perm.object_id
                    and not assigned_perm.content_type
                )
            ]

            if (pk_field_name := relation_model._meta.pk.name) == "id":
                owner_based_relation = (
                    "id" if self.owner_relation == "*" else f"{self.owner_relation}_id"
                )
            else:
                owner_based_relation = (
                    pk_field_name
                    if self.owner_relation == "*"
                    else f"{self.owner_relation}__{pk_field_name}"
                )

            owner_based_q = (
                Q(**{f"{owner_based_relation}__in": owner_based_matches})
                if owner_based_matches
                else None
            )

        directly_authorized_ids = [
            assigned_perm.object_id
            for assigned_perm in context.assigned_perms
            if (
                assigned_perm.perm == context.perm
                and assigned_perm.content_type == self.model_content_type
            )
        ]
        q = Q(pk__in=directly_authorized_ids) if directly_authorized_ids else None

        if q and owner_based_q:
            return q | owner_based_q

        return q or owner_based_q

    def get_resources_q_from_indirect_perms(self, context: Context) -> Optional[Q]:
        q = None

        for indirect_perms in self.get_scheme_indirect_perms(context):
            if context.perm in indirect_perms.can_receive_perms():
                if (
                    indirect_perms_q := indirect_perms.get_resources_q(context)
                ) is not None:
                    if not q:
                        q = indirect_perms_q
                    else:
                        q |= indirect_perms_q

        return q

    def get_resources_implicit_conditions_q(self, context: Context) -> Optional[Q]:
        """
        The resulting Q is meant to be AND-ed with other Qs, and not to be used on it's own.
        A `None` result means the Q is guaranteed to be logically False.
        """

        implicit_conditions_qs = [
            condition.get_resources_q(context)
            for condition in self.get_scheme_implicit_conditions(context) or []
        ]
        if not implicit_conditions_qs:
            return Q()

        return merge_qs(implicit_conditions_qs)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        if context.assigned_perms is None:
            context.assigned_perms = AssignedPerm.objects.filter(
                self.get_assigned_perms_q(context)
            )

        q = merge_qs(
            [
                self.get_resources_q_from_directly_assigned_perms(context),
                self.get_resources_q_from_indirect_perms(context),
            ],
            connector=Q.OR,
        )

        q = merge_qs([q, self.get_resources_implicit_conditions_q(context)])

        # TODO check if this restriction is ok; also handle list of specific resources
        if isinstance(context.resource, Model):
            if not context.resource.pk:
                raise ValueError(
                    "Encountered context.resource without pk", context.resource
                )

            if q is not None:
                q &= Q(pk=context.resource.pk)

        return q

    def is_directly_authorized_for_prefetched_resource(self, context: Context) -> bool:
        # TODO: improve the description for this method
        # It is assumed that context.assigned_perms have been prefetched with scheme.get_assigned_perms_q()
        # or such that the User has membership to the UserGroups and what other implicit conditions the scheme
        # may specify.

        for assigned_perm in context.assigned_perms:
            if assigned_perm.perm != context.perm:
                # Skip if the perms don't match
                continue

            if assigned_perm.content_type:
                model = assigned_perm.content_type.model_class()
                if model != context.resource.__class__:
                    # Skip if the perm is granted to another model
                    continue

                if assigned_perm.object_id and model._meta.pk.to_python(assigned_perm.object_id) == context.resource.pk:
                    # Match if the object_id matches (and the model matches too)
                    return True

            if not assigned_perm.object_id:
                # Match if the perm is granted to any object with model=resource.model or model=None
                return True

        return False

    def is_authorized_for_prefetched_resource(self, context: Context) -> bool:
        if context.assigned_perms is None:
            context.assigned_perms = AssignedPerm.objects.filter(
                self.get_assigned_perms_q(context)
            )

        if context.memberships is None:
            q = self.get_memberships_q(context)
            if q is None:
                context.memberships = Membership.objects.none()
            else:
                context.memberships = Membership.objects.filter(
                    self.get_memberships_q(context)
                )

        for condition in self.get_scheme_implicit_conditions(context) or []:
            if not condition.is_authorized_for_prefetched_resource(context):
                return False

        if self.is_directly_authorized_for_prefetched_resource(context):
            return True

        for indirect_perm in self.get_scheme_indirect_perms(context):
            if context.perm not in indirect_perm.can_receive_perms():
                continue

            if indirect_perm.is_authorized_for_prefetched_resource(context):
                return True

        return False

    def is_authorized_for_unsaved_resource(self, context: Context) -> bool:
        for condition in self.get_scheme_implicit_conditions(context) or []:
            if not condition.is_authorized_for_unsaved_resource(context):
                return False

        for indirect_perm in self.get_scheme_indirect_perms(context):
            if context.perm not in indirect_perm.can_receive_perms():
                continue

            if indirect_perm.is_authorized_for_unsaved_resource(context):
                return True

        return False

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        q = merge_qs(
            [
                self.get_directly_assigned_perms_q(context),
                self.get_indirectly_assigned_perms_q(context),
            ],
            connector=Q.OR,
        )

        for condition in self.get_scheme_implicit_conditions(context) or []:
            if (condition_q := condition.get_assigned_perms_q(context)) is not None:
                if q is None:
                    q = condition_q
                else:
                    q |= condition_q

        return q

    def get_directly_assigned_perms_q(self, context: Context) -> Optional[Q]:
        if not self.allow_directly_assigned_perms:
            return None

        q = Q(
            user_group__memberships__is_outside_collaborator=False,
            user_group__memberships__user=context.actor,
            perm=context.perm,
        )
        target_resources_q = Q(
            content_type=None, object_id=None
        )  # TODO: is this OK for listing all allowed stuff?

        if context.resource:
            if isinstance(context.resource, Model):
                target_resources_q |= Q(
                    content_type=ContentType.objects.get_for_model(self.model),
                    object_id=context.resource.pk,
                )
            else:
                target_resources_q |= Q(
                    content_type=ContentType.objects.get_for_model(self.model),
                )

        q &= target_resources_q

        return q

    def get_indirectly_assigned_perms_q(self, context: Context) -> Optional[Q]:
        qs = []

        for indirect_perm in self.get_scheme_indirect_perms(context):
            if context.perm not in indirect_perm.can_receive_perms():
                continue

            if (
                indirect_perm_q := indirect_perm.get_assigned_perms_q(context)
            ) is not None:
                qs.append(indirect_perm_q)

        if not qs:
            return None

        return reduce(lambda q1, q2: q1 | q2, qs)

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        q = None
        qs = []

        for indirect_perm in self.get_scheme_indirect_perms(context):
            if context.perm not in indirect_perm.can_receive_perms():
                continue

            if (
                indirect_perm_q := indirect_perm.get_memberships_q(context)
            ) is not None:
                qs.append(indirect_perm_q)

        if qs:
            q = reduce(lambda q1, q2: q1 | q2, qs)

        for condition in self.get_scheme_implicit_conditions(context) or []:
            if (condition_q := condition.get_memberships_q(context)) is not None:
                if q is None:
                    q = condition_q
                else:
                    q |= condition_q

        return q

    def get_auth_scheme_by_relation(self, relation) -> "ModelAuthorizationScheme":
        return get_relation_scheme(self, relation)

    def get_model_for_relation(self, relation) -> type[Model]:
        return self.get_auth_scheme_by_relation(relation).model

    def get_auth_scheme_for_direct_relation(
        self, relation
    ) -> "ModelAuthorizationScheme":
        # TODO: this should raise if there are 2 or more auth classes for the same model
        result = self.auth_solver.get_auth_scheme_for_model(
            self.get_model_for_direct_relation(relation)
        )

        return result

    def get_model_for_direct_relation(self, relation) -> type[Model]:
        result = self.model._meta.get_field(relation).related_model
        if not result:
            raise ValueError(f"No model for relation {relation}")

        return result

    @property
    def model_content_type(self) -> ContentType:
        if not self.model:
            raise ValueError("Missing model.")

        return ContentType.objects.get_for_model(self.model)

    def __str__(self):
        return self.__class__.__name__


def get_relation_scheme(
    initial_scheme: ModelAuthorizationScheme, relation: str
) -> ModelAuthorizationScheme:
    if relation == "*":
        return initial_scheme

    intermediary_relations = relation.split("__")
    related_scheme = initial_scheme

    for relation in intermediary_relations:
        related_scheme = related_scheme.get_auth_scheme_for_direct_relation(relation)

    return related_scheme
