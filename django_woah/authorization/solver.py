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

from inspect import isclass
from typing import Optional

from django.contrib.auth import get_user_model
from django.db.models import Q, Model, Manager, Subquery

from django_woah.models import AssignedPerm, Membership
from django_woah.utils.q import merge_qs, optimize_q, pop_parts_of_q
from .context import Context, CombinedContext
from .enum import PermEnum
from .scheme import ModelAuthorizationScheme


class AuthorizationSolver:
    def __init__(
        self,
        authorization_schemes: list[
            ModelAuthorizationScheme | type[ModelAuthorizationScheme]
        ],
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

    def clean_perm(
        self, dirty_perm: str | PermEnum
    ) -> tuple[PermEnum, ModelAuthorizationScheme]:
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

    def get_memberships_q(self, context: Context) -> Optional[Q]:
        _, scheme = self.clean_perm(context.perm)

        q = scheme.get_memberships_q(context)

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
        perm: str | PermEnum,
        resource=None,
        prefetch_assigned_perms=True,
        extra: Optional[dict] = None,
        **kwargs,
    ) -> Context:
        if isinstance(perm, PermEnum):
            perm, _ = self.clean_perm(perm)

        if extra is None:
            extra = {}

        context = Context(
            actor=actor, perm=perm, resource=resource, extra=extra, **kwargs
        )

        if prefetch_assigned_perms and "assigned_perms" not in kwargs:
            context.assigned_perms = self.get_assigned_perms_queryset(context)

        return context

    def get_context_no_actor(
        self,
        perm: str | PermEnum,
        resource=None,
        prefetch_assigned_perms=True,
        prefetch_memberships=True,
        extra: Optional[dict] = None,
        **kwargs,
    ) -> Context:
        if isinstance(perm, PermEnum):
            perm, _ = self.clean_perm(perm)

        if extra is None:
            extra = {}

        # Use a Fake actor to get assigned_perms_q and memberships
        class FakePK(int):
            def is_fake(self):
                return True

        context = Context(
            actor=get_user_model()(pk=FakePK(-1)),
            perm=perm,
            resource=resource,
            extra=extra,
            **kwargs,
        )

        # Strip the Fake actor from the assigned perms Q to fetch all the potentially needed ones
        assigned_perms_q = pop_parts_of_q(
            self.get_assigned_perms_q(context),
            matcher=lambda key, *values: key == "user_group__memberships__user"
            and values[0] == context.actor,
        )

        # TODO: See how to extract this into a separate method, maybe the existing get_assigned_perms_queryset
        if prefetch_assigned_perms and "assigned_perms" not in kwargs:
            context.assigned_perms = AssignedPerm.objects.filter(assigned_perms_q)

        # TODO: See how to extract this into a separate method
        if prefetch_memberships and "memberships" not in kwargs:
            memberships_q = Q(
                user_group__in=[
                    assigned_perm.user_group_id
                    for assigned_perm in context.assigned_perms
                ]
            )

            if (additional_q := self.get_memberships_q(context)) is not None:
                # Strip the fake actor from the memberships Q to fetch all the potentially needed ones
                additional_q = pop_parts_of_q(
                    additional_q,
                    matcher=lambda key, *values: key == "user"
                    and values[0] == context.actor,
                )

                memberships_q |= additional_q

            context.memberships = Membership.objects.filter(memberships_q)

        context.actor = None

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
            model = resources

            if not isclass(model):
                model = model[0].__class__

        return model

    def get_authorized_actors_q(self, context: Context) -> Optional[Q]:
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
                assigned_perms_by_user_group_id[assigned_perm.user_group_id] = [
                    assigned_perm
                ]
            else:
                assigned_perms_by_user_group_id[assigned_perm.user_group_id].append(
                    assigned_perm
                )

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

            if scheme.is_authorized_for_prefetched_resource(subcontext):
                authorized_actors_ids.append(actor_id)

        if not authorized_actors_ids:
            return None

        return Q(id__in=authorized_actors_ids)

    def get_authorized_actors_queryset(self, context: Context):
        actor_class = get_user_model()

        q = self.get_authorized_actors_q(context)
        if q is None:
            return actor_class.objects.none()

        return actor_class.objects.filter(q)

    def get_authorized_on_resources_q(self, context: Context) -> Optional[Q]:
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

    def get_authorized_on_resources_queryset(
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

        q = merge_qs(
            [self.get_authorized_on_resources_q(context) for context in contexts]
        )

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

    def is_authorized_for_prefetched_resource(
        self, context: Optional[Context] = None, **kwargs
    ) -> bool:
        if not context:
            context = self.get_context(**kwargs)

        if not context.resource:
            raise ValueError("Must specify resource")

        if not isinstance(context.resource, Model):
            raise ValueError(
                f"Expected resource to be a Model instance, but got: {context.resource}"
            )

        model = context.resource.__class__
        scheme = self.get_auth_scheme_for_model(model)

        return scheme.is_authorized_for_prefetched_resource(context)

    def is_authorized_for_unsaved_resource(
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

            if not scheme.is_authorized_for_unsaved_resource(context):
                return False

        return True


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
