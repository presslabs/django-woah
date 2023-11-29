import enum

from dataclasses import dataclass, field
from functools import reduce
from typing import Optional, Callable, Union

from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q, Model, Subquery, Manager

from django_woah.models import AssignedPerm, UserGroup
from django_woah.utils.q import (
    prefix_q_with_relation,
    verify_resource_by_q,
    get_object_relation,
    optimize_q,
    merge_qs,
)


class PermEnum(enum.StrEnum):
    def __repr__(self):
        if not hasattr(self, "auth_scheme"):
            return super().__repr__()

        value_repr = self.__class__._value_repr_ or repr

        return "<%s.%s.%s: %s>" % (
            self.auth_scheme.__name__,
            self.__class__.__name__,
            self._name_,
            value_repr(self._value_),
        )

    @classmethod
    def values(cls):
        return list(cls)


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


def get_relation_scheme(
    initial_scheme: "AuthorizationScheme", relation: str
) -> "AuthorizationScheme":
    if relation == "*":
        return initial_scheme

    intermediary_relations = relation.split("__")
    related_scheme = initial_scheme

    for relation in intermediary_relations:
        related_scheme = related_scheme.get_auth_scheme_for_direct_relation(relation)

    return related_scheme


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

    def __init__(self, *conditions: Condition, operation=type[OPERATIONS], **kwargs):
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
            self.related_scheme = get_relation_scheme(self.scheme, self.relation)
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
        # context.resource = self.scheme.get_auth_scheme_for_relation(
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
        self.relation_scheme = self.scheme.get_auth_scheme_for_relation(self.relation)

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

        context.resource = self.scheme.get_auth_scheme_for_relation(self.relation).model
        context.assigned_perms = solver.get_assigned_perms_queryset(context)

        return solver.get_authorized_resources_queryset(context).exists()


class AuthorizationScheme:
    owner_relation: str
    model: Optional[Model]
    Perms: PermEnum
    direct_authorization_is_allowed = True

    def __init__(self):
        auth_solver: AuthorizationSolver  # noqa: F842

    def __init_subclass__(cls, **kwargs):
        for value in getattr(cls, "Perms", []):
            value.auth_scheme = cls
            value.is_permission = True
            value.is_role = False

        for value in getattr(cls, "Roles", []):
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
            perms_and_roles = roles.values() + perms_and_roles

        if perms := getattr(cls, "Perms", []):
            perms_and_roles = perms.values() + perms_and_roles

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

        if not self.direct_authorization_is_allowed:
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
                relation = (
                    "id" if self.owner_relation == "*" else f"{self.owner_relation}_id"
                )
            else:
                relation = (
                    pk_field_name
                    if self.owner_relation == "*"
                    else f"{self.owner_relation}__{pk_field_name}"
                )

            owner_based_q = (
                Q(**{f"{relation}__in": owner_based_matches})
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

    def get_resources_q(self, context: Context) -> Optional[Q]:
        if context.assigned_perms is None:
            context.assigned_perms = AssignedPerm.objects.filter(
                self.get_assigned_perms_q(context)
            )

        q = self.get_resources_q_from_directly_assigned_perms(context)

        for indirect_perms in self.get_scheme_indirect_perms(context):
            if context.perm in indirect_perms.can_receive_perms():
                if (
                    indirect_perms_q := indirect_perms.get_resources_q(context)
                ) is not None:
                    if q:
                        q |= indirect_perms_q
                    else:
                        q = indirect_perms_q

        if q is None:
            return None

        for condition in self.get_scheme_implicit_conditions(context) or []:
            implicit_condition_q = condition.get_resources_q(context)
            if implicit_condition_q is None:
                return None

            q &= implicit_condition_q

        # TODO check if this restriction is ok; also handle list of specific resources
        if isinstance(context.resource, Model):
            if not context.resource.pk:
                raise ValueError(
                    "Encountered context.resource without pk", context.resource
                )

            if q is not None:
                q &= Q(pk=context.resource.pk)

        return q

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
        if not self.direct_authorization_is_allowed:
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

    def get_auth_scheme_for_relation(self, relation) -> "AuthorizationScheme":
        return get_relation_scheme(self, relation)

    def get_model_for_relation(self, relation) -> Optional[type[Model]]:
        return self.get_auth_scheme_for_relation(relation).model

    def get_auth_scheme_for_direct_relation(self, relation) -> "AuthorizationScheme":
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
        return ContentType.objects.get_for_model(self.model)

    def __str__(self):
        return self.__class__.__name__


class AuthorizationSolver:
    def __init__(
        self,
        authorization_schemes: list[AuthorizationScheme | type[AuthorizationScheme]],
    ):
        self.authorization_schemes: list[AuthorizationScheme] = []

        for scheme in authorization_schemes:
            if not isinstance(scheme, AuthorizationScheme):
                scheme = scheme()

            scheme.auth_solver = self
            self.authorization_schemes.append(scheme)

    def clean_perm(
        self, dirty_perm: str | PermEnum
    ) -> tuple[PermEnum, AuthorizationScheme]:
        for scheme in self.authorization_schemes:
            for perm in getattr(scheme, "Perms", []):
                if dirty_perm == perm:
                    return perm, scheme

            for perm in getattr(scheme, "Roles", []):
                if dirty_perm == perm:
                    return perm, scheme

        raise ValueError(f"Unexpected perm received: {dirty_perm}")

    def get_assigned_perms_q(self, context: Context) -> Optional[Q]:
        _, scheme = self.clean_perm(context.perm)

        q = scheme.get_assigned_perms_q(context)

        return q

    def get_assigned_perms_queryset(
        self,
        root_context: Context | CombinedContext,
    ):
        contexts = (
            root_context.contexts
            if isinstance(root_context, CombinedContext)
            else [root_context]
        )

        assigned_perms_q = merge_qs(
            [self.get_assigned_perms_q(context) for context in contexts], connector=Q.OR
        )

        if assigned_perms_q is None:
            return AssignedPerm.objects.none()

        return AssignedPerm.objects.filter(assigned_perms_q)

    def get_context(
        self,
        actor,
        perm: Optional[str | PermEnum],
        resource=None,
        prefetch_assigned_perms=True,
        extra: Optional[dict] = None,
    ) -> Context:
        if perm and not isinstance(perm, PermEnum):
            perm, _ = self.clean_perm(perm)

        context = Context(actor=actor, perm=perm, resource=resource, extra=extra)

        if prefetch_assigned_perms:
            context.assigned_perms = self.get_assigned_perms_queryset(context)

        return context

    def get_auth_scheme_for_model(self, model: type[Model]):
        for scheme in self.authorization_schemes:
            if scheme.model == model:
                return scheme

        raise ValueError(f"No AuthScheme for model {model}")

    def get_model(self, resources):
        if isinstance(resources, Model):
            model = resources.__class__
        elif isinstance(resources, Manager):
            model = resources.model
        elif issubclass(resources, Model):
            model = resources
        else:
            model = resources[0].__class__

        return model

    def get_authorized_resources_q(self, context: Context) -> Optional[Q]:
        if not context.resource:
            raise ValueError("Must specify resource")

        if context.assigned_perms is None:
            raise ValueError("Missing context assigned_perms")

        model = self.get_model(context.resource)
        scheme = self.get_auth_scheme_for_model(model)

        resources_q = scheme.get_resources_q(context)
        if resources_q is None:
            return None

        return optimize_q(resources_q, allow_bools=False)

    def get_authorized_resources_queryset(
        self,
        context: Optional[Context | CombinedContext] = None,
        base_queryset=None,
        **kwargs,
    ):
        if not context:
            context = self.get_context(**kwargs)

        if isinstance(context, CombinedContext):
            contexts = context.contexts
        else:
            contexts = [context]

        model = self.get_model(contexts[0].resource)

        q = merge_qs([self.get_authorized_resources_q(context) for context in contexts])

        if q is None:
            return model.objects.none()

        if base_queryset is None:
            base_queryset = model.objects

        return model.objects.filter(
            pk__in=Subquery(base_queryset.filter(q).values("pk").distinct())
        )

    def is_authorized_for_unsaved_resource(
        self, context: Optional[Context | CombinedContext] = None, **kwargs
    ):
        if not context:
            context = self.get_context(**kwargs)

        if isinstance(context, CombinedContext):
            contexts = context.contexts
        else:
            contexts = [context]

        for context in contexts:
            if not context.resource:
                raise ValueError("Must specify resource")

            if not isinstance(context.resource, Model):
                raise ValueError(
                    f"Expected resource to be a Model instance, but got: {context.resource}"
                )

            model = context.resource.__class__
            scheme = self.get_auth_scheme_for_model(model)

            if not scheme.is_authorized_for_unsaved_resource(context):
                return False

        return True
