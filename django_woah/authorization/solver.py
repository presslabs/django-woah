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

from typing import Optional

from django.db.models import Q, Model, Manager, Subquery

from django_woah.models import AssignedPerm
from django_woah.utils.q import merge_qs, optimize_q
from .context import Context, CombinedContext
from .enum import PermEnum
from .scheme import ModelAuthorizationScheme


class AuthorizationSolver:
    def __init__(
        self,
        authorization_schemes: list[ModelAuthorizationScheme | type[ModelAuthorizationScheme]],
    ):
        self.authorization_schemes: list[ModelAuthorizationScheme] = []

        for scheme in authorization_schemes:
            if not isinstance(scheme, ModelAuthorizationScheme):
                scheme = scheme()

            scheme.auth_solver = self
            self.authorization_schemes.append(scheme)

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
    ) -> Context:
        if not isinstance(perm, PermEnum):
            perm, _ = self.clean_perm(perm)

        if extra is None:
            extra = {}

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
