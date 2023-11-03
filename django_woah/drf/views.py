from collections import defaultdict

from rest_framework.exceptions import MethodNotAllowed
from rest_framework.permissions import IsAuthenticated

from django_woah.drf.permission import IsAuthorized
from django_woah.authorization import AuthorizationSolver, PermEnum

uninitialized = object()


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
    def model(self):
        return self.serializer_class.Meta.model

    def get_authorization_relation(self):
        return getattr(self, "authorization_relation", None)

    def get_authorized_model_lookup_url_kwarg(self):
        return getattr(self, "authorized_model_lookup_url_kwarg", None)

    def get_authorized_model_lookup_field(self):
        return getattr(self, "authorized_model_lookup_field", None)

    @property
    def authorization_model(self):
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

        if method not in self.perms_map:
            raise MethodNotAllowed(method)

        return self.perms_map[method]

    def get_actor(self):
        return self.request.user

    def get_authorization_context(self, extra=None):
        cache_key = self.get_cache_key("get_authorization_context")
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        context = self.authorization_solver.get_context(
            # TODO fix multiple permissions
            perm=self.get_required_permissions(),
            actor=self.get_actor(),
            resource=self.authorization_model,
            extra=extra,
        )

        self._cache[cache_key] = context

        return context

    def get_authorization_model_queryset(self):
        cache_key = self.get_cache_key("get_authorization_model_queryset")
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        queryset = self.authorization_solver.get_authorized_resources_queryset(
            # TODO fix multiple permissions
            perm=self.get_required_permissions(),
            context=self.get_authorization_context(),
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

    def get_authorization_model_object(self):
        cache_key = self.get_cache_key("get_authorization_model_object")
        cached_result = self._cache[cache_key]

        if cached_result is not uninitialized:
            return cached_result

        lookup_url_kwarg = self.get_authorized_model_lookup_url_kwarg()
        if lookup_url_kwarg and self.kwargs.get(lookup_url_kwarg) is None:
            return None

        obj = self.get_authorization_model_queryset().first()

        self._cache[cache_key] = obj

        return obj

    def get_requested_model_queryset(self):
        if self.model == self.authorization_model:
            return self.get_authorization_model_queryset()

        return self.model.objects.filter(
            **{
                f"{self.get_authorization_relation()}__in": self.get_authorization_model_queryset()
            }
        )

    def is_authorized_for_unsaved_resource(self):
        # TODO move this in context initialization
        context = self.get_authorization_context()
        serializer = self.get_serializer()

        context.resources = serializer.Meta.model(
            **serializer.to_internal_value(self.request.data)
        )
        context.resources.clean()
        print(
            "is_authorized_for_unsaved_resource!!!!",
            serializer.to_internal_value(self.request.data),
        )

        return self.authorization_solver.is_authorized_for_unsaved_resource(
            # TODO fix multiple permissions
            perm=self.get_required_permissions(),
            context=context,
        )
