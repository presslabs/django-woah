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

from collections import defaultdict

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Model
from django.db.models import Q
from django.http import Http404
from rest_framework.exceptions import (
    MethodNotAllowed,
    PermissionDenied,
    ValidationError,
)
from rest_framework.fields import empty
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import GenericViewSet
from typing import Optional

from django_woah.authorization import PermEnum
from django_woah.authorization.context import CombinedContext
from django_woah.authorization.solver import AuthorizationSolver
from django_woah.drf.permission import IsAuthorized
from django_woah.utils.q import merge_qs

uninitialized = object()

validation_error_setting = "AUTHORIZATION_UNSAVED_RESOURCE_VALIDATION_ERRORS"
clean_unsaved_resource_setting = "AUTHORIZATION_UNSAVED_RESOURCE_CLEAN_BEFORE"
validation_error_message = (
    "The unsaved resource on which the authorization is being run against has validation errors.\n"
    f"To easily avoid most of these situations, you may set {validation_error_setting} = False"
    "in your app settings, but beware of the (rare) potential pitfalls.\n"
    "Check the base `get_unsaved_resource` method on your view to find more about it."
)


class AuthorizationViewSetMixin:
    authorization_solver: AuthorizationSolver

    permission_classes = [IsAuthenticated, IsAuthorized]

    def __init__(self, *args, **kwargs):
        self._cache = defaultdict(lambda: uninitialized, {})

        super().__init__(*args, **kwargs)

    cache_separator = object()

    def get_cache_key(self, key, *args, **kwargs):
        return (
            (key,)
            + (self.cache_separator,)
            + args
            + (self.cache_separator,)
            + tuple(sorted(kwargs.items()))
        )

    @property
    def model(self) -> type[Model]:
        if queryset := getattr(self, "queryset", None):
            return queryset.model

        if serializer_class := self.get_serializer_class():
            return serializer_class.Meta.model

        raise ValueError("A model property must be defined on your view.")

    def get_authorization_relation(self):
        return getattr(self, "authorization_relation", None)

    def get_authorized_model_lookup_url_kwarg(self):
        return getattr(
            self,
            "authorized_model_lookup_url_kwarg",
            getattr(self, "lookup_url_kwarg", None),
        )

    def get_authorized_model_lookup_field(self):
        return getattr(
            self, "authorized_model_lookup_field", getattr(self, "lookup_field", None)
        )

    @property
    def authorization_model(self) -> type[Model]:
        auth_relation_field = self.get_authorization_relation()
        if not auth_relation_field:
            return self.model

        return self.model._meta.get_field(auth_relation_field).remote_field.model

    def get_required_permissions(self) -> list[PermEnum]:
        """
        A perms_map in the style of DRF's `DjangoModelPermissions` can be defined on the view.
        Here's a random example:

        perms_map = {
            'GET': [XYZScheme.Perms.ViewXYZ],
            'OPTIONS': [XYZScheme.Perms.ViewXYZ],
            'HEAD': [XYZScheme.Perms.ViewXYZ],
            'POST': [XYZScheme.Perms.CreateXYZ],
            'PUT': [XYZScheme.Perms.EditXYZ],
            'PATCH': [XYZScheme.Perms.EditXYZ],
            'DELETE': [XYZScheme.Perms.ViewXYZ, XYZScheme.Perms.DeleteXYZ],
        }
        """

        if not hasattr(self, "perms_map"):
            raise NotImplementedError(
                "Provide a `perms_map` dict or implement the `get_required_permissions` method in the view."
            )

        method = self.request.method

        perms = self.perms_map.get(method)
        if perms is None:
            if method == "OPTIONS":
                if getattr(self, "authorize_options_as_get", True):
                    perms = self.perms_map.get("GET")

        if perms is None:
            raise MethodNotAllowed(method)

        if isinstance(perms, (str, PermEnum)):
            perms = [perms]

        return perms

    def get_actor(self):
        return self.request.user

    def get_authorization_context_extra(self, perm: str | PermEnum) -> dict:
        return {}

    def get_authorization_context(self) -> CombinedContext:
        cache_key = self.get_cache_key("get_authorization_context")
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        context = CombinedContext()

        for perm in self.get_required_permissions():
            if not isinstance(perm, PermEnum):
                perm, _ = self.authorization_solver.clean_perm(perm)

            context.add(
                self.authorization_solver.get_context(
                    actor=self.get_actor(),
                    perm=perm,
                    resource=self.authorization_model,
                    extra=self.get_authorization_context_extra(perm),
                    prefetch_assigned_perms=False,
                )
            )

        context.assigned_perms = self.authorization_solver.get_assigned_perms_queryset(
            context
        )

        self._cache[cache_key] = context

        return context

    def get_authorization_model_q(self) -> Optional[Q]:
        cache_key = self.get_cache_key("get_authorization_model_q")
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        qs = []

        for context in self.get_authorization_context().contexts:
            qs.append(
                self.authorization_solver.get_authorized_resources_q(context=context)
            )

        q = merge_qs(qs)

        if q is not None and self.kwargs.get(
            self.get_authorized_model_lookup_url_kwarg()
        ):
            q &= Q(
                **{
                    self.get_authorized_model_lookup_field(): self.kwargs.get(
                        self.get_authorized_model_lookup_url_kwarg()
                    )
                }
            )

        self._cache[cache_key] = q

        return q

    def get_authorization_model_queryset(self, base_queryset=None):
        cache_key = self.get_cache_key(
            "get_authorization_model_queryset", base_queryset=base_queryset
        )
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        queryset = self.authorization_solver.get_authorized_resources_queryset(
            context=self.get_authorization_context(),
            base_queryset=base_queryset,
        )

        if self.kwargs.get(self.get_authorized_model_lookup_url_kwarg()):
            queryset = queryset.filter(
                **{
                    self.get_authorized_model_lookup_field(): self.kwargs.get(
                        self.get_authorized_model_lookup_url_kwarg()
                    )
                }
            )

        self._cache[cache_key] = queryset

        return queryset

    def get_authorization_model_object(
        self, skip_authorization=False
    ) -> Optional[Model]:
        cache_key = self.get_cache_key(
            "get_authorization_model_object", skip_authorization=skip_authorization
        )
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        lookup_url_kwarg = self.get_authorized_model_lookup_url_kwarg()
        if lookup_url_kwarg and self.kwargs.get(lookup_url_kwarg) is None:
            return None

        queryset = self.authorization_model.objects.filter(
            **{
                self.get_authorized_model_lookup_field(): self.kwargs.get(
                    lookup_url_kwarg
                )
            }
        )
        if not skip_authorization:
            queryset = self.get_authorization_model_queryset(base_queryset=queryset)

        obj = queryset.first()

        self._cache[cache_key] = obj

        return obj

    def get_requested_model_queryset(self):
        queryset = getattr(self, "queryset", None)

        if self.model == self.authorization_model:
            return self.get_authorization_model_queryset(base_queryset=queryset)

        if not queryset:
            queryset = self.model.objects

        return queryset.filter(
            **{
                f"{self.get_authorization_relation()}__in": self.get_authorization_model_queryset()
            }
        )

    def get_unsaved_resource(self) -> Model:
        """
        This method is used to obtain an instance of the unsaved resource against which authorization will be run.
        It is written such that it minimizes the cases where exceptions are raised, in case of ValidationErrors,
        or fields which don't exist on the model or are reverse relations and cannot be instantiated as such.

        It's possible that in some weird and rare cases, this will result in a wrong authorization decision.

        For example:
        - when reverse relations should be part of the validation, because those are not handled here.
            - using the `unsaved_object_relation` field, in the AuthorizationScheme, might help in some of these cases
        - when certain fields fail validation (even if that case should result in a validation error eventually).
        """

        raise_exception = getattr(settings, validation_error_setting, True)
        raised = False

        serializer = self.get_serializer(data=self.request.data)
        model = serializer.Meta.model

        reverse_relations = [
            f.name
            for f in model._meta.get_fields()
            if f.auto_created and not f.concrete
        ]

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data
        except (ValidationError, DjangoValidationError):
            if raise_exception:
                raised = True
                raise

            serializer_fields = serializer.fields
            data = {}

            for field_name, field in serializer_fields.items():
                if field.source == "*" or field.read_only:
                    continue

                if (field_value := field.get_value(self.request.data)) != empty:
                    try:
                        data[field.source] = field.to_internal_value(field_value)
                    except (ValidationError, DjangoValidationError):
                        continue
        finally:
            if raised:
                print(validation_error_message)

        data = {k: v for k, v in data.items() if k not in reverse_relations}

        resource = serializer.Meta.model(**data)
        if getattr(
            self,
            "authorization_clean_unsaved_resource",
            getattr(settings, clean_unsaved_resource_setting, True),
        ):
            try:
                resource.clean()
            except DjangoValidationError:
                if raise_exception:
                    raised = True
                    raise
            finally:
                if raised:
                    print(validation_error_message)

        return resource

    def is_authorized_for_unsaved_resource(self) -> bool:
        # TODO move this in context initialization
        combined_context = self.get_authorization_context()

        if self.authorization_model != self.model:
            # If the authorization model is different from the one being serialized it makes no sense
            # to use get_unsaved_resource, so get_authorization_model_object is used as it's probably
            # the one deciding the authorization

            # TODO: enable this optimization, but only when lookup_field == model.pk field
            # if lookup_value := self.kwargs.get(
            #     self.get_authorized_model_lookup_url_kwarg()
            # ):
            #     context.resource = self.authorization_model(
            #         **{self.get_authorized_model_lookup_field(): lookup_value}
            #     )
            # else:
            resource = self.get_authorization_model_object(skip_authorization=True)
            for context in combined_context.contexts:
                context.resource = resource

            return self.authorization_solver.get_authorized_resources_queryset(
                context=combined_context,
            ).exists()

        resource = self.get_unsaved_resource()

        if resource is None:
            return False

        for context in combined_context.contexts:
            context.resource = resource

        return self.authorization_solver.is_authorized_for_unsaved_resource(
            context=combined_context,
        )


class AuthorizationGenericViewSet(AuthorizationViewSetMixin, GenericViewSet):
    def get_queryset(self):
        return self.get_requested_model_queryset()

    def get_object(self):
        try:
            return super().get_object()
        except Http404:
            raise PermissionDenied()
