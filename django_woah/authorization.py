import enum

import copy
from dataclasses import dataclass, field
from functools import reduce
from typing import Optional, Callable

from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q, Model

from django_woah.models import Authorization, UserGroup


class PermEnum(enum.StrEnum):
    def __repr__(self):
        if not hasattr(self, "auth_scheme"):
            return super().__repr__()

        v_repr = self.__class__._value_repr_ or repr

        return "<%s.%s.%s: %s>" % (
            self.auth_scheme.__name__,
            self.__class__.__name__,
            self._name_,
            v_repr(self._value_),
        )

    @classmethod
    def values(cls):
        return list(cls)


@dataclass
class Context:
    actor: Optional[AbstractUser] = None
    authorizations: Optional[list[Authorization]] = None
    resources: Optional[Model | list[Model]] = None
    extra: dict = field(default_factory=dict)

    _root: Optional["Context"] = None

    def subcontext(self):
        subcontext = copy.copy(self)
        subcontext._root = subcontext._root or self._root

        return subcontext


def prefix_q_with_relation(q: Q, relation: str) -> Q:
    children = []

    for child in q.children:
        if isinstance(child, Q):
            children.append(prefix_q_with_relation(child, relation))
        elif isinstance(child, tuple):
            children.append((f"{relation}__{child[0]}", *child[1:]))
        else:
            raise (ValueError("Unexpected child", child))

    return Q(*children, _connector=q.connector, _negated=q.negated)


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


def get_object_relation(obj, relation: str):
    if relation == "*":
        return obj

    for intermediary_attr in relation.split("__"):
        obj = getattr(obj, intermediary_attr)

    return obj


def verify_resource_by_q(resource, q: Q) -> bool:
    result = True

    for child in q.children:
        if q.connector == Q.OR:
            operator = result.__or__
        elif q.connector == Q.AND:
            operator = result.__and__
        else:
            raise ValueError("Unexpected Q operator", q.connector)

        if isinstance(child, Q):
            result = operator(verify_resource_by_q(resource, child))
        elif isinstance(child, tuple):
            return get_object_relation(resource, child[0]) == child[1]
        else:
            raise ValueError("Unexpected child", child)

    return result


class Condition:
    def resources_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        raise NotImplementedError

    def authorizations_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        return None

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        return False

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

    def __init__(self, *conditions: Condition, operation=type[OPERATIONS]):
        self.conditions = conditions
        self.operation = operation

    def resources_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        result = Q()

        for condition in self.conditions:
            if (q := condition.resources_q(perm, context)) is None:
                return None

            if self.operation == self.OPERATIONS.AND:
                result &= q
            elif self.operation == self.OPERATIONS.OR:
                result |= q
            else:
                raise ValueError("Unexpected Condition operation")

        return result

    def authorizations_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        return reduce(
            lambda q1, q2: q1 | q2,
            [
                q
                for condition in self.conditions
                if (q := condition.authorizations_q(perm, context)) is not None
            ],
        )

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        result = True

        for condition in self.conditions:
            ok = condition.is_authorized_for_unsaved_resource(perm, context)

            if self.operation == self.OPERATIONS.AND:
                result &= ok
            elif self.operation == self.OPERATIONS.OR:
                result |= ok
            else:
                raise ValueError("Unexpected Condition operation")

        return result


class HasMembership(Condition):
    def __init__(
        self,
        scheme: "AuthorizationScheme",
        actor,
        include_outside_collaborators=False,
    ):
        relation_model = (
            scheme.model
            if scheme.owner_relation == "*"
            else scheme.get_model_for_relation(scheme.owner_relation)
        )
        self.relation_is_user_group = relation_model == UserGroup
        self.relation = scheme.owner_relation
        self.actor = actor
        self.include_outside_collaborators = include_outside_collaborators

    def resources_q(self, _: PermEnum, __: Context) -> Q:
        user_groups_relation = (
            "owned_user_groups__" if not self.relation_is_user_group else ""
        )
        relation = "" if self.relation == "*" else f"{self.relation}__"

        query = {
            f"{relation}{user_groups_relation}memberships__user": self.actor,
            f"{relation}{user_groups_relation}kind": "root",
        }
        if self.include_outside_collaborators is not None:
            query[
                f"{relation}{user_groups_relation}memberships__is_outside_collaborator"
            ] = self.include_outside_collaborators

        return Q(**query)

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        resource = context.resources

        owner = get_object_relation(resource, self.relation)

        if not self.relation_is_user_group:
            owner = owner.related_user_groups

        if isinstance(owner, UserGroup):
            if not owner.kind == "root":
                return False

        query = {"user": self.actor}

        if self.include_outside_collaborators is not None:
            query["is_outside_collaborator"] = self.include_outside_collaborators

        print("HASMEMBERSHIP.is_authorized_for_unsaved_resource", query)
        return owner.memberships.filter(**query).exists()


class HasSameResourcePerms(Condition):
    def __init__(self, scheme: "AuthorizationScheme", perms: list[PermEnum]):
        self.scheme = scheme
        self.perms = perms

    def resources_q(self, _: PermEnum, context: Context) -> Optional[Q]:
        qs = [self.scheme.get_resources_q(perm, context) for perm in self.perms]

        if not qs:
            return None

        return reduce(lambda q1, q2: q1 & q2, qs)

    def authorizations_q(self, _: PermEnum, context: Context) -> Q:
        return reduce(
            lambda q1, q2: q1 | q2,
            [
                q
                for perm in self.perms
                if (q := self.scheme.get_authorizations_q(perm, context))
            ],
        )

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        solver = self.scheme.auth_solver

        return all(
            solver.get_authorized_resources_queryset(perm, context)
            for perm in self.perms
        )


class HasRelatedResourcePerms(Condition):
    def __init__(
        self, scheme: "AuthorizationScheme", relation: str, perms: list[PermEnum]
    ):
        if not isinstance(perms, (list, set, tuple)):
            raise ValueError(f"Received perms of type {type(perms)}: {perms}")

        self.scheme = scheme
        self.relation = relation
        # check if relation actually exists on auth model.
        self.related_scheme = get_relation_scheme(self.scheme, self.relation)

        self.perms = perms

    def resources_q(self, _: PermEnum, context: Context) -> Optional[Q]:
        context = context.subcontext()
        context.resources = self.related_scheme.model

        qs = [
            prefix_q_with_relation(q, self.relation)
            for perm in self.perms
            if ((q := self.related_scheme.get_resources_q(perm, context)) is not None)
        ]

        if not qs:
            return None

        return reduce(lambda q1, q2: q1 & q2, qs)

    def authorizations_q(self, _: PermEnum, context: Context) -> Q:
        context = context.subcontext()
        context.resources = self.scheme.get_auth_scheme_for_relation(
            self.relation
        ).model

        related_scheme = self.scheme.get_auth_scheme_for_relation(self.relation)

        return reduce(
            lambda q1, q2: q1 | q2,
            [related_scheme.get_authorizations_q(perm, context) for perm in self.perms],
        )

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        context = context.subcontext()
        context.resources = get_object_relation(context.resources, self.relation)

        solver = self.scheme.auth_solver

        context.resources = self.scheme.get_auth_scheme_for_relation(
            self.relation
        ).model
        # TODO: Fix multiple perms here
        context.authorizations = solver.get_authorizations_queryset(
            self.perms[0], context
        )

        print("is_authorized_for_unsaved_resource", context.resources, perm)

        return all(
            solver.get_authorized_resources_queryset(perm, context).exists()
            for perm in self.perms
        )


class HasUnrelatedResourcePerms(Condition):
    def __init__(self, scheme: "AuthorizationScheme", resource, perms: list[PermEnum]):
        if not isinstance(perms, (list, set, tuple)):
            raise ValueError(f"Received perms of type {type(perms)}: {perms}")

        self.scheme = scheme
        self.resource = resource

        self.perms = perms

    def resources_q(self, _: Optional[PermEnum], context: Context) -> Optional[Q]:
        context = context.subcontext()
        context.resources = self.resource

        solver = self.scheme.auth_solver

        print("HasUnrelatedResourcePerms!!!", self.resource, self.perms, context)

        if all(
            self.resource in solver.get_authorized_resources_queryset(perm, context)
            for perm in self.perms
        ):
            return Q()

        return None

    def authorizations_q(self, perm: PermEnum, context: Context) -> Q:
        context = context.subcontext()
        context.resources = self.scheme.auth_solver

        solver = self.scheme.auth_solver

        return reduce(
            lambda q1, q2: q1 | q2,
            [solver.get_authorizations_q(perm, context) for perm in self.perms],
        )

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        return self.resources_q(None, context) == Q()


class QCondition(Condition):
    def __init__(
        self, q: Q, authorize_unsaved_resource_func: Optional[Callable] = None
    ):
        self.q = q
        self.authorize_unsaved_resource_func = authorize_unsaved_resource_func

    def resources_q(self, _: PermEnum, __: Context) -> Q:
        return self.q

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        if self.authorize_unsaved_resource_func:
            return self.authorize_unsaved_resource_func(context)

        return verify_resource_by_q(context.resources, self.q)


class IndirectPerms:
    def can_receive_perms(self) -> list[PermEnum]:
        return []

    def resources_q(self, perm: PermEnum, context: Context) -> Q:
        raise NotImplementedError

    def authorizations_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        raise NotImplementedError

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        raise NotImplementedError


class ConditionalPerms(IndirectPerms):
    def __init__(self, conditions: list[Condition], receives_perms: list[PermEnum]):
        self.conditions = conditions
        self.receives_perms = receives_perms

    def resources_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        subqs = [condition.resources_q(perm, context) for condition in self.conditions]

        for subq in subqs:
            if subq is None:
                return None

        return reduce(lambda q1, q2: q1 & q2, subqs)

    def authorizations_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        qs = [
            q
            for condition in self.conditions
            if (q := condition.authorizations_q(perm, context))
        ]

        if not qs:
            return None

        return reduce(
            lambda q1, q2: q1 | q2,
            qs,
        )

    def can_receive_perms(self):
        return self.receives_perms

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        return all(
            condition.is_authorized_for_unsaved_resource(perm, context)
            for condition in self.conditions
        )


class TransitiveFromRelationPerms(IndirectPerms):
    def __init__(
        self, scheme: "AuthorizationScheme", relation: str, restrict_to_perms=None
    ):
        self.scheme = scheme
        self.relation = relation
        self.restrict_to_perms = set(restrict_to_perms or []).intersection(
            scheme.Perms.values()
        )
        self.relation_scheme = self.scheme.get_auth_scheme_for_relation(self.relation)

        if not self.restrict_to_perms:
            self.restrict_to_perms = scheme.Perms.values()

    def resources_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        context = context.subcontext()
        context.resources = self.relation_scheme.model

        if perm not in self.restrict_to_perms:
            raise ValueError(
                f"{perm} not in restrict_to_perms {self.restrict_to_perms}"
            )

        q = self.relation_scheme.get_resources_q(perm, context)
        if q is None:
            return None

        return prefix_q_with_relation(q, self.relation)

    def authorizations_q(self, perm: PermEnum, context: Context) -> Q:
        context = context.subcontext()
        context.resources = self.relation_scheme.model

        return self.relation_scheme.get_authorizations_q(perm, context)

    def can_receive_perms(self) -> list[PermEnum]:
        return self.restrict_to_perms

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        if perm not in self.restrict_to_perms:
            raise ValueError(
                f"{perm} not in restrict_to_perms {self.restrict_to_perms}"
            )

        context = context.subcontext()
        context.resources = get_object_relation(context.resources, self.relation)

        solver = self.scheme.auth_solver

        context.resources = self.scheme.get_auth_scheme_for_relation(
            self.relation
        ).model
        context.authorizations = solver.get_authorizations_queryset(perm, context)

        print("is_authorized_for_unsaved_resource", context.resources, perm)

        return solver.get_authorized_resources_queryset(perm, context).exists()


class AuthorizationScheme:
    owner_relation: str
    model: Optional[Model]
    Perms: PermEnum

    def __init__(self):
        auth_solver: AuthorizationSolver

    def __init_subclass__(cls, **kwargs):
        for value in getattr(cls, "Perms", []):
            value.auth_scheme = cls
            value.is_permission = True
            value.is_role = False

        for value in getattr(cls, "Roles", []):
            value.auth_scheme = cls
            value.is_permission = False
            value.is_role = True

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return []

    def get_implicit_conditions(
        self, perm: PermEnum, context: Context
    ) -> list[Condition]:
        return []

    def get_direct_perms_resources_q(
        self, perm: PermEnum, authorizations
    ) -> Optional[Q]:
        relation_model = self.get_model_for_relation(self.owner_relation)

        print(
            "AUTHORIZATIONS",
            authorizations,
            perm,
            [(a.object_id, a.content_type, a.role) for a in authorizations],
        )
        owner_based_matches = [
            a.root.owner_id if relation_model != UserGroup else a.root_id
            for a in authorizations
            if (not a.object_id and not a.content_type and a.role == perm)
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
        print("RELATION", relation)

        print(self, "owner_based_q", owner_based_q)

        direct_authorizations = [
            a.object_id
            for a in authorizations
            if (a.content_type == self.model_content_type and a.role == perm)
        ]
        q = Q(pk__in=direct_authorizations) if direct_authorizations else None

        print("Q", q)
        if q and owner_based_q:
            return q | owner_based_q

        return q or owner_based_q

    def get_resources_q(self, perm: PermEnum, context: Context) -> Optional[Q]:
        if not context.authorizations:
            context.authorizations = Authorization.objects.filter(
                self.get_authorizations_q(perm, context)
            )

        q = self.get_direct_perms_resources_q(perm, context.authorizations)
        print(
            "CONTEXT AUTHORIZATIONS", context.authorizations, context.resources, perm, q
        )

        for indirect_perms in self.get_indirect_perms(context):
            if perm in indirect_perms.can_receive_perms():
                if (
                    indirect_perms_q := indirect_perms.resources_q(perm, context)
                ) is not None:
                    if q:
                        q |= indirect_perms_q
                    else:
                        q = indirect_perms_q

        if q is None:
            print("PERM IS NONE", perm, self.get_implicit_conditions(perm, context))
            return None

        for condition in self.get_implicit_conditions(perm, context) or []:
            implicit_condition_q = condition.resources_q(perm, context)
            if implicit_condition_q is None:
                print("IMPLICIT PERM IS NONE", perm, condition)
                return None

            q &= implicit_condition_q

        return q

    def is_authorized_for_unsaved_resource(
        self, perm: PermEnum, context: Context
    ) -> bool:
        for condition in self.get_implicit_conditions(perm, context) or []:
            if not condition.is_authorized_for_unsaved_resource(perm, context):
                print("IMPLICIT CONDITION IS FALSE!!!", condition, perm)
                return False

        for indirect_perm in self.get_indirect_perms(context):
            if perm not in indirect_perm.can_receive_perms():
                continue

            print("testing INDIRECT PERM", indirect_perm)
            if indirect_perm.is_authorized_for_unsaved_resource(perm, context):
                return True

            print("INDIRECT CONDITION IS FALSE!!!", indirect_perm, perm)

        print("is_authorized_for_unsaved_resource!!!", False)
        return False

    def get_authorizations_q(self, perm: PermEnum, context: Context) -> Q:
        q = self.get_direct_authorizations_q(perm, context)
        print("!!get_authorizations_q", self, "direct_auth_q", q)

        indirect_authorizations_q = self.get_indirect_authorizations_q(perm, context)
        print(
            "!!get_authorizations_q",
            self,
            "indirect_authorizations_q",
            indirect_authorizations_q,
        )
        if indirect_authorizations_q is not None:
            q |= indirect_authorizations_q

        for condition in self.get_implicit_conditions(perm, context) or []:
            if (condition_q := condition.authorizations_q(perm, context)) is not None:
                q |= condition_q

        return q

    def get_direct_authorizations_q(self, perm: PermEnum, context=None) -> Q:
        q = Q(
            user_group__memberships__is_outside_collaborator=False,
            user_group__memberships__user=context.actor,
            role=perm,
        )
        target_resources_q = Q(
            content_type=None, object_id=None
        )  # TODO: is this OK for listing all allowed stuff?

        if context.resources:
            # TODO: context.resources might only matter for the first level, for indirect stuff it might as well not matter?
            # VERRRRY IMPORTANT
            # Also check why authorizations Q are fetched before all qs are done
            if isinstance(context.resources, Model):
                target_resources_q |= Q(
                    content_type=ContentType.objects.get_for_model(self.model),
                    object_id=context.resources.pk,
                )
            elif isinstance(context.resources, list):
                raise ValueError(
                    "WARNING !!! IGNORING context.resources LIST", context.resources
                )
            else:
                # TODO: decide if this stays
                target_resources_q |= Q(
                    content_type=ContentType.objects.get_for_model(self.model),
                )

        q &= target_resources_q

        return q

    def get_indirect_authorizations_q(
        self, perm: PermEnum, context=None
    ) -> Optional[Q]:
        qs = []

        for indirect_perm in self.get_indirect_perms(context):
            if perm not in indirect_perm.can_receive_perms():
                continue

            if indirect_perm_q := indirect_perm.authorizations_q(perm, context):
                qs.append(indirect_perm_q)

        if not qs:
            return None

        return reduce(lambda q1, q2: q1 | q2, qs)

    def get_auth_scheme_for_relation(self, relation) -> "AuthorizationScheme":
        return get_relation_scheme(self, relation)

    def get_model_for_relation(self, relation) -> type[Model]:
        return self.get_auth_scheme_for_relation(relation).model

    def get_auth_scheme_for_direct_relation(self, relation) -> "AuthorizationScheme":
        # ToDo: this should raise if there are 2 or more auth classes for the same model
        # So specifying classes for relation should be allowed somehow (maybe having different solvers is enough)
        result = self.auth_solver.get_auth_scheme_for_model(
            self.get_model_for_direct_relation(relation)
        )
        print("!!get_auth_scheme_for_relation", relation, result)

        return result

    def get_model_for_direct_relation(self, relation) -> type[Model]:
        print(
            "!!get_model_for_relation",
            relation,
            self.model._meta.get_field(relation).related_model,
        )
        return self.model._meta.get_field(relation).related_model

    @property
    def model_content_type(self) -> ContentType:
        return ContentType.objects.get_for_model(self.model)


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

    def get_authorizations_q(self, perm: PermEnum, context: Context) -> Q:
        perm, scheme = self.clean_perm(perm)
        print("SCHEME FOR AUTHS", perm, scheme)

        return scheme.get_authorizations_q(perm, context)

    def get_authorizations_queryset(self, perm: PermEnum, context):
        auth_q = self.get_authorizations_q(perm, context)
        print("Q FOR AUTHS", auth_q)

        return Authorization.objects.filter(auth_q).select_for_update()

    def get_context(
        self,
        perm: PermEnum,
        actor,
        resource=None,
        fetch_authorizations=True,
        extra: Optional[dict] = None,
    ) -> Context:
        context = Context(actor=actor, resources=resource, extra=extra)

        if fetch_authorizations:
            context.authorizations = self.get_authorizations_queryset(perm, context)
            print(
                "JUST FETCHED THE AUTHORIZATIONS QUERYSET IN VIEW",
                list(context.authorizations),
            )

        return context

    def get_auth_scheme_for_model(self, model: type[Model]):
        for scheme in self.authorization_schemes:
            if scheme.model == model:
                return scheme

        raise ValueError(f"No AuthScheme for model {model}")

    def get_authorized_resources_queryset(self, perm: str | PermEnum, context):
        if not isinstance(perm, PermEnum):
            perm, _ = self.clean_perm(perm)

        if not context.resources:
            raise ValueError("Must specify resource")

        if context.authorizations is None:
            raise ValueError("Missing context authorizations")

        print("RESOURCES!!!", context.resources)
        if isinstance(context.resources, Model):
            model = context.resources.__class__
        elif issubclass(context.resources, Model):
            model = context.resources
        else:
            model = context.resources[0].__class__

        scheme = self.get_auth_scheme_for_model(model)

        resources_q = scheme.get_resources_q(perm, context)
        print("authorized_resources q", resources_q, model)
        if resources_q is None:
            return model.objects.none()

        return model.objects.filter(resources_q)

    def is_authorized_for_unsaved_resource(self, perm: str | PermEnum, context):
        if not isinstance(perm, PermEnum):
            perm, _ = self.clean_perm(perm)

        if not context.resources:
            raise ValueError("Must specify resource")

        if not isinstance(context.resources, Model):
            raise ValueError(
                f"Expected resource to be a Model instance, but got: {context.resources}"
            )

        model = context.resources.__class__
        scheme = self.get_auth_scheme_for_model(model)

        return scheme.is_authorized_for_unsaved_resource(perm, context)
