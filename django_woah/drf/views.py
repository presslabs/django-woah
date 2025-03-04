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
from rest_framework import mixins
from rest_framework.exceptions import (
    MethodNotAllowed,
    PermissionDenied,
    ValidationError,
)
from rest_framework.fields import empty
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import GenericViewSet
from typing import Optional

from django_woah.authorization import (
    PermEnum,
    AuthorizationScheme,
    ModelAuthorizationScheme,
    HasSameResourcePerms,
)
from django_woah.authorization.context import CombinedContext, Context
from django_woah.authorization.solver import AuthorizationSolver
from django_woah.drf.fields import PermissionsField
from django_woah.drf.permission import IsAuthorized
from django_woah.models import AssignedPerm
from django_woah.utils.q import merge_qs, pop_parts_of_q, optimize_q

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

    @property
    def authorization_scheme(self) -> ModelAuthorizationScheme:
        return self.authorization_solver.get_auth_scheme_for_model(
            self.authorization_model
        )

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

        authorization_context = CombinedContext()

        required_perms = self.get_required_permissions()

        for perm in required_perms:
            if not isinstance(perm, PermEnum):
                perm, _ = self.authorization_solver.clean_perm(perm)

            authorization_context.add(
                self.authorization_solver.get_context(
                    actor=self.get_actor(),
                    perm=perm,
                    resource=self.authorization_model,
                    extra=self.get_authorization_context_extra(perm),
                    prefetch_assigned_perms=False,
                    prefetch_memberships=False,
                )
            )

        if self._expected_to_get_perms():
            special_context = CombinedContext()

            for perm in self.authorization_scheme.get_scheme_perms():
                special_context.add(
                    self.authorization_solver.get_context(
                        actor=self.get_actor(),
                        perm=perm,
                        resource=self.authorization_model,
                        extra=self.get_authorization_context_extra(perm),
                        prefetch_assigned_perms=False,
                        prefetch_memberships=False,
                    )
                )

            # Strip scheme perm from Q since we're fetching all of them anyway; optimize_q also helps to reduce the Q
            q = optimize_q(
                pop_parts_of_q(
                    self.authorization_solver.get_assigned_perms_q(special_context),
                    matcher=lambda *elements: (
                        elements[0] == "perm"
                        and elements[1].auth_scheme
                        == self.authorization_scheme.__class__
                    ),
                )
            )

            authorization_context.assigned_perms = AssignedPerm.objects.filter(q)
        else:
            authorization_context.assigned_perms = (
                self.authorization_solver.get_assigned_perms_queryset(
                    authorization_context
                )
            )

        self._cache[cache_key] = authorization_context

        return authorization_context

    def get_authorization_model_q(self) -> Optional[Q]:
        cache_key = self.get_cache_key("get_authorization_model_q")
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        qs = []

        for context in self.get_authorization_context().contexts:
            qs.append(self.authorization_solver.get_resources_q(context=context))

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

        queryset = self.authorization_solver.get_resources_queryset(
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

    def _expected_to_get_perms(self):
        cache_key = "_expected_to_get_perms"
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        expected = False
        if hasattr(self, "get_serializer_class"):
            try:
                serializer_class = self.get_serializer_class()
            except AssertionError:
                # The unlikely case of a ViewSet with undefined serializer_class logic... It's not our business.
                serializer_class = None
        else:
            serializer_class = getattr(self, "serializer_class", None)

        if serializer_class:
            try:
                fields = serializer_class().get_fields()
            except (AttributeError, KeyError):
                # Missing context["view"] resulting in serializer_class() KeyError.
                # Serializer not being a model serialize resulting in .get_fields() AttributeError.
                return False

            for field in fields.values():
                if isinstance(field, PermissionsField):
                    expected = True
                    break

        self._cache[cache_key] = expected

        return expected

    def get_base_context_for_get_perms(self):
        """
        Only call this method once filtering based on the authorization has been performed!
        """

        cache_key = "get_base_context_for_get_perms"
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        root_context = self.get_authorization_context()

        context_for_memberships = CombinedContext()
        context_for_memberships.assigned_perms = root_context.assigned_perms

        # Because of filtering and pagination (and how DRF methods are badly composed), we expect to have the resources
        # that are about to be serialized in this attribute... The default viewset implementation (not this mixin)
        # overrides the `.get_serializer()` method to achieve this.
        returned_resources = getattr(self, "resources_to_be_serialized", None)

        if not returned_resources:
            # If the resources haven't been pinned, well... we run the same duplicated filtering and pagination logic.
            returned_resources = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(returned_resources)
            if page:
                returned_resources = page

        for resource in returned_resources:
            context_for_memberships.add(
                Context(
                    actor=root_context.contexts[0].actor, perm=None, resource=resource
                )
            )

        context = Context(
            actor=root_context.contexts[0].actor, perm=None, resource=resource
        )
        context.assigned_perms = context_for_memberships.assigned_perms

        context.memberships = list(
            [
                m
                for m in self.authorization_solver.get_memberships_queryset(
                    context_for_memberships
                )
            ]
        )

        self._cache[cache_key] = context

        return context

    def get_perms_for_resource(self, resource):
        base_context = self.get_base_context_for_get_perms()
        context = base_context.subcontext(resource=resource)

        return self.authorization_solver.get_perms(context).get(
            (self.get_actor(), resource), []
        )

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
        cache_key = self.get_cache_key("get_requested_model_queryset")
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        queryset = getattr(self, "queryset", None)

        if self.model == self.authorization_model:
            queryset = self.get_authorization_model_queryset(base_queryset=queryset)

        else:
            if not queryset:
                queryset = self.model.objects

            queryset = queryset.filter(
                **{
                    f"{self.get_authorization_relation()}__in": self.get_authorization_model_queryset()
                }
            )

        self._cache[cache_key] = queryset

        return queryset

    def get_unsaved_resource(self, initial_obj=None) -> Model:
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

        if not initial_obj:
            resource = serializer.Meta.model(**data)
        else:
            resource = initial_obj

            for k, v in data.items():
                setattr(resource, k, v)

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

        try:
            authorization_model = self.authorization_model
        except AttributeError:
            authorization_model = None

        try:
            resource_model = self.model
        except AttributeError:
            resource_model = None

        if authorization_model != resource_model:
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

            return self.authorization_solver.get_resources_queryset(
                context=combined_context,
            ).exists()

        try:
            resource = self.get_unsaved_resource()

            if resource is None:
                return False

            for context in combined_context.contexts:
                context.resource = resource

            return self.authorization_solver.verify_authorization(
                context=combined_context,
            )
        except (AttributeError, ValueError):
            if not self.request.data:
                # DRF has this "nice" way of testing if it should render a POST form in the default browsable API
                serializer = self.get_serializer(data=self.request.data)

                if not serializer.is_valid(raise_exception=False):
                    # If the payload is not valid, it means we can allow authorization to pass since it will fail
                    # at the validation step even if it were a real request
                    # This will allow a POST form to be rendered in the browsable API, instead of getting a 500 error
                    return True

            raise


class AuthorizationGenericViewSet(AuthorizationViewSetMixin, GenericViewSet):
    def get_queryset(self):
        return self.get_requested_model_queryset()

    def get_object(self):
        try:
            return super().get_object()
        except Http404:
            raise PermissionDenied()

    def get_serializer(self, *args, **kwargs):
        if args:
            resources = args[0]
            if isinstance(resources, Model):
                resources = [resources]

            setattr(self, "resources_to_be_serialized", resources)

        return super().get_serializer(*args, **kwargs)


class AuthorizationModelViewSet(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    AuthorizationGenericViewSet,
):
    pass
