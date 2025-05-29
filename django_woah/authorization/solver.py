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
import time
from inspect import isclass
from typing import Optional

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.db.models import Q, Model, Manager, Subquery, QuerySet
from django.utils.functional import lazy

from django_woah.models import AssignedPerm, Membership
from django_woah.utils.q import merge_qs, optimize_q, pop_parts_of_q, repr_q
from .context import Context, CombinedContext
from .enum import PermEnum
from .scheme import ModelAuthorizationScheme
from ..utils.logic import at_least_x_truthy
from ..utils.models import FakePK


class AuthorizationSolver:
    def __init__(
        self,
        authorization_schemes: list[ModelAuthorizationScheme | type[ModelAuthorizationScheme]],
        clean_perms=True,
    ):
        self.authorization_schemes: list[ModelAuthorizationScheme] = []

        for scheme in authorization_schemes:
            if not isinstance(scheme, ModelAuthorizationScheme):
                scheme = scheme()

            scheme.auth_solver = self
            self.authorization_schemes.append(scheme)

        if clean_perms:
            perms = {}

            for scheme in self.authorization_schemes:
                for perm in scheme.get_scheme_perms(exclude_borrowed=True):
                    if perm.value in perms:
                        raise ValueError(
                            f"Found {perm.value} in both {perm.auth_scheme} and {perms[perm.value].auth_scheme}"
                        )

                    perms[perm.value] = perm

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
    #     if item in ["get_memberships_q", "verify_authorization"]:
    #         return wrapper(super().__getattribute__(item))
    #
    #     return super().__getattribute__(item)

    def clean_perm(self, dirty_perm: str | PermEnum) -> tuple[PermEnum, ModelAuthorizationScheme]:
        for scheme in self.authorization_schemes:
            for perm in getattr(scheme, "Perms", []):
                if dirty_perm == perm:
                    return perm, scheme

            for perm in getattr(scheme, "Roles", []):
                if dirty_perm == perm:
                    return perm, scheme

        extra = ""
        if isinstance(dirty_perm, PermEnum):
            if hasattr(dirty_perm, "auth_scheme"):
                extra = f". Maybe you forgot to pass the {dirty_perm.auth_scheme} class when initializing the {self}?"
            else:
                extra = f". Maybe you mistyped the class name where you defined {dirty_perm}?"

        raise ValueError(f"Unexpected perm received: {dirty_perm}{extra}")

    def get_assigned_perms_q(self, root_context: Context | CombinedContext) -> Optional[Q]:
        contexts = (
            root_context.contexts if isinstance(root_context, CombinedContext) else [root_context]
        )

        assigned_perms_q = None
        for context in contexts:
            _, scheme = self.clean_perm(context.perm)

            if not context.actor:
                context.actor = get_user_model()(pk=FakePK(-1))

            q = scheme.get_assigned_perms_q(context)

            if isinstance(context.actor.pk, FakePK):
                # Strip the Fake actor from the assigned perms Q to fetch all the potentially needed ones
                if q:
                    q = pop_parts_of_q(
                        q,
                        matcher=lambda key, *values: key == "user_group__memberships__user"
                        and values[0] == context.actor,
                    )

                context.actor = None

            assigned_perms_q = merge_qs([assigned_perms_q, q], connector=Q.OR)

        return assigned_perms_q

    def get_assigned_perms_queryset(
        self,
        root_context: Context | CombinedContext
    ):
        assigned_perms_q = self.get_assigned_perms_q(root_context)

        if assigned_perms_q is None:
            return AssignedPerm.objects.none()

        if isinstance(root_context, CombinedContext) and len(root_context.contexts) > 5:
            assigned_perms_q = optimize_q(assigned_perms_q, allow_bools=False)

            if assigned_perms_q is None:
                return AssignedPerm.objects.none()

        return AssignedPerm.objects.filter(assigned_perms_q)

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        """
        This method addresses all potentially required Memberships, but each Condition and other similar implementations
        must make sure they filter/validate them. For example there might be memberships to root user group of different
        resources, or memberships to Team or single User UserGroups, not to just Root ones...
        """

        # TODO: maybe treat case when context.assigned_perms is None; either raise or use a different Q
        q = Q(
            user_group__in=tuple(set(
                assigned_perm.user_group_id for assigned_perm in context.assigned_perms or []
            ))
        )

        resource = context.resource

        if isinstance(resource, Model):
            scheme = self.get_auth_scheme_for_model(resource.__class__)
        else:
            scheme = self.get_auth_scheme_for_model(resource)

        if not context.actor:
            context.actor = get_user_model()(pk=FakePK(-1))

        scheme_q = scheme.get_memberships_q(context)

        if isinstance(context.actor.pk, FakePK):
            # Strip the fake actor from the memberships Q to fetch all the potentially needed ones
            if scheme_q:
                scheme_q = pop_parts_of_q(
                    scheme_q,
                    matcher=lambda key, *values: key == "user" and values[0] == context.actor,
                )

            context.actor = None

        q = merge_qs([q, scheme_q], connector=Q.OR)

        return optimize_q(q, allow_bools=False)

    def get_memberships_queryset(
        self,
        root_context: Context | CombinedContext
    ):
        """
        This method returns all potentially required Memberships, but each Condition and other similar implementations
        must make sure they filter/validate them. For example there might be memberships to root user group of different
        resources, or memberships to Team or single User UserGroups, not to just Root ones...
        """

        contexts = (
            root_context.contexts if isinstance(root_context, CombinedContext) else [root_context]
        )

        memberships_q = merge_qs(
            [self.get_memberships_q(context) for context in contexts], connector=Q.OR
        )
        if isinstance(root_context, CombinedContext):
            memberships_q = optimize_q(memberships_q, allow_bools=False)

        return Membership.objects.filter(memberships_q).select_related("user_group")

    def get_context(
        self,
        actor: AbstractUser=None,
        perm: str | PermEnum=None,
        resource=None,
        prefetch_assigned_perms=True,
        prefetch_memberships=True,
        extra: Optional[dict] = None,
        **kwargs,
    ) -> Context:
        if not at_least_x_truthy([actor, perm, resource], x=2):
            raise ValueError("You must specify at least 2 params out of `actor`, `perm` and `resource`.")

        if isinstance(perm, (str, PermEnum)):
            perm, scheme = self.clean_perm(perm)

            if not resource:
                resource = scheme.model

        elif perm is not None:
            raise ValueError(f"Got unexpected perm {perm} of type {type(perm)}.")

        if extra is None:
            extra = {}

        context = Context(actor=actor, perm=perm, resource=resource, extra=extra)

        if "assigned_perms" in kwargs:
            context.assigned_perms = kwargs.pop("assigned_perms")
        elif prefetch_assigned_perms:
            context.assigned_perms = self.get_assigned_perms_queryset(context)

        if "memberships" in kwargs:
            context.memberships = kwargs.pop("memberships")
        elif prefetch_memberships:
            # We lazily call because solver.get_memberships_queryset also forces the context.assigned_perms QuerySet
            # to evaluate, which we don't want to until it's necessary...
            context.memberships = lazy(self.get_memberships_queryset, QuerySet)(context)

        return context

    def get_auth_scheme_for_model(self, model: type[Model]) -> ModelAuthorizationScheme:
        for scheme in self.authorization_schemes:
            if scheme.model == model:
                return scheme

        raise ValueError(f"No AuthScheme for model {model}")

    def get_model(self, resources) -> type[Model]:
        if isinstance(resources, Model):
            model = resources.__class__
        elif isinstance(resources, Manager):
            model = resources.model
        elif issubclass(resources, Model):
            model = resources
        else:
            model = resources

            if not isclass(model):
                model = model[0].__class__

        return model

    def get_actors_q(self, context: Context) -> Optional[Q]:
        if context.actor is not None:
            raise ValueError("Must not specify context actor")

        if not context.resource:
            raise ValueError("Must specify context resource")

        if context.assigned_perms is None:
            raise ValueError("Must specify context assigned_perms")

        if context.memberships is None:
            raise ValueError("Must specify context memberships")

        model = self.get_model(context.resource)
        scheme = self.get_auth_scheme_for_model(model)

        assigned_perms_by_user_group_id = {}

        for assigned_perm in context.assigned_perms:
            if assigned_perm.user_group_id not in assigned_perms_by_user_group_id:
                assigned_perms_by_user_group_id[assigned_perm.user_group_id] = [assigned_perm]
            else:
                assigned_perms_by_user_group_id[assigned_perm.user_group_id].append(assigned_perm)

        actors_context_data = {}

        for membership in context.memberships:
            actor_id = membership.user_id

            if not actors_context_data.get(actor_id):
                actors_context_data[actor_id] = {
                    "memberships": [membership],
                    "assigned_perms": assigned_perms_by_user_group_id.get(
                        membership.user_group_id, []
                    ),
                }
            else:
                actors_context_data[actor_id]["memberships"].append(membership)
                actors_context_data[actor_id]["assigned_perms"] += (
                    assigned_perms_by_user_group_id.get(membership.user_group_id, [])
                )

        actor_class = get_user_model()
        authorized_actors_ids = []

        for actor_id, context_data in actors_context_data.items():
            subcontext = context.subcontext()
            subcontext.actor = actor_class(id=actor_id)
            subcontext.assigned_perms = context_data["assigned_perms"]
            subcontext.memberships = context_data["memberships"]

            if scheme.verify_authorization(subcontext):
                authorized_actors_ids.append(actor_id)

        if not authorized_actors_ids:
            return None

        return Q(pk__in=authorized_actors_ids)

    def get_actors_queryset(self, context: Context):
        actor_class = get_user_model()

        q = self.get_actors_q(context)
        if q is None:
            return actor_class.objects.none()

        return actor_class.objects.filter(q)

    def get_resources_q(self, context: Context) -> Optional[Q]:
        if not context.resource:
            raise ValueError("Must specify context resource")

        if context.assigned_perms is None:
            raise ValueError("Must specify context assigned_perms")

        model = self.get_model(context.resource)
        scheme = self.get_auth_scheme_for_model(model)

        resources_q = scheme.get_resources_q(context)
        if resources_q is None:
            return None

        return optimize_q(resources_q, allow_bools=False)

    def get_resources_queryset(
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

        q = merge_qs([self.get_resources_q(context) for context in contexts])

        if q is None:
            return model.objects.none()

        if base_queryset is None:
            base_queryset = model.objects.all()

        # Copy the base_queryset, detach it's ordering, and attach it to the new queryset
        order_by = base_queryset.query.order_by
        extra_order_by = base_queryset.query.extra_order_by
        default_ordering = base_queryset.query.default_ordering

        base_queryset.query.clear_ordering()

        queryset = model.objects.filter(
            pk__in=Subquery(base_queryset.filter(q).values("pk").distinct())
        )

        queryset.query.order_by = order_by
        queryset.query.extra_order_by = extra_order_by
        queryset.query.default_ordering = default_ordering

        return queryset

    def verify_authorization(
        self, context: Optional[Context | CombinedContext] = None, **kwargs
    ) -> bool:
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

            if not scheme.verify_authorization(context):
                return False

        return True

    def get_perms(self, context: Optional[Context | CombinedContext] = None, **kwargs) -> dict[tuple[Model, Model], list[PermEnum]]:
        if not context:
            context = self.get_context(**kwargs, prefetch_assigned_perms=False, prefetch_memberships=False)

        if isinstance(context, CombinedContext):
            contexts = context.contexts
        else:
            contexts = [context]

        model = contexts[0].resource.__class__
        if not issubclass(model, Model):
            raise ValueError(f"Expected resource to be a Model instance, but got: {contexts[0].resource}")

        scheme = self.get_auth_scheme_for_model(model)

        perms_hierarchy = scheme.get_perms_pseudo_hierarchy(
            contexts[0]  # We can't use a CombinedContext here, so although this is not correct, it's fine
        )
        scheme_perms = sorted(
            scheme.get_scheme_perms(),
            key=lambda perm: perms_hierarchy[perm],
            reverse=False,
        )

        perms_by_actor_resource = {}

        for context in contexts:
            if context.perm:
                raise ValueError("Must not specify perms")

            if not isinstance(context.resource, model):
                raise ValueError(
                    f"Expected resource to be a {model} instance, but got: {context.resource}"
                )

            key = context.actor, context.resource
            if key in perms_by_actor_resource:
                raise ValueError("Found duplicate (context.actor, context.resource) pair in CombinedContext.")

            perms = []

            for perm in scheme_perms:
                subcontext = context.subcontext(perm)

                if self.verify_authorization(subcontext):
                    perms.append(perm)

            perms_by_actor_resource[key] = perms

        return perms_by_actor_resource


# def gather_schemes():
#     sub_schemes = AuthorizationScheme.__subclasses__()
#     leaf_schemes = []
#
#     for scheme in sub_schemes:
#         if not scheme.__subclasses__():
#             leaf_schemes.append(scheme)
#         else:
#             leaf_schemes.extend(gather_schemes(scheme))
#
#     return leaf_schemes
#
# DefaultAuthorizationSolver = AuthorizationSolver(
#     authorization_schemes=gather_schemes()
# )
