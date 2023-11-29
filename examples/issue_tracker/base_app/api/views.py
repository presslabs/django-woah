from rest_framework.viewsets import ModelViewSet

from django_woah.drf.views import AuthorizationViewSetMixin

from .serializers import (
    IssueSerializer,
    AccountSummarySerializer,
    MembershipSerializer,
    UserGroupSerializer,
    AssignedPermSerializer,
)
from ..authorization import (
    AuthorizationSolver,
    IssueAuthorizationScheme,
    AccountAuthorizationScheme,
    MembershipAuthorizationScheme,
    UserGroupAuthorizationScheme,
    AssignedPermAuthorizationScheme,
)


class IssueViewSet(AuthorizationViewSetMixin, ModelViewSet):
    serializer_class = IssueSerializer
    lookup_field = "uuid"
    lookup_url_kwarg = "issue_id"

    authorization_solver = AuthorizationSolver

    perms_map = {
        "GET": IssueAuthorizationScheme.Perms.ISSUE_VIEW,
        "POST": IssueAuthorizationScheme.Perms.ISSUE_CREATE,
    }

    def get_queryset(self):
        return self.get_requested_model_queryset()


class AccountViewSet(AuthorizationViewSetMixin, ModelViewSet):
    serializer_class = AccountSummarySerializer
    lookup_field = "uuid"
    lookup_url_kwarg = "account_id"

    authorization_solver = AuthorizationSolver

    perms_map = {
        "GET": AccountAuthorizationScheme.Perms.ACCOUNT_VIEW,
        "DELETE": AccountAuthorizationScheme.Perms.ACCOUNT_DELETE,
    }

    def get_queryset(self):
        return self.get_requested_model_queryset()


class MembershipViewSet(AuthorizationViewSetMixin, ModelViewSet):
    serializer_class = MembershipSerializer
    lookup_field = "uuid"
    lookup_url_kwarg = "membership_id"

    authorization_solver = AuthorizationSolver

    perms_map = {
        "GET": MembershipAuthorizationScheme.Perms.MEMBERSHIP_VIEW,
        "POST": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
    }

    def get_queryset(self):
        return self.get_requested_model_queryset()

    # def get_authorization_relation(self):
    #     # TODO: A difference between is_action_authorized and filter_authorized_resources might
    #     # prove to be useful, for cases like this one. Or where there is no model object to begin with.
    #
    #     if self.request.method == "POST":
    #         return "user_group"
    #
    #     return super().get_authorization_relation()

    # def get_authorization_model_object(self):
    #     if self.request.method == "POST":
    #         user_group_pk = self.request.data["user_group"].pk
    #
    #         return self.authorization_solver.get_authorized_resources_queryset()
    #
    #     return super().get_authorization_model_object()


class UserGroupViewSet(AuthorizationViewSetMixin, ModelViewSet):
    serializer_class = UserGroupSerializer
    lookup_field = "uuid"
    lookup_url_kwarg = "user_group_id"

    authorization_solver = AuthorizationSolver

    perms_map = {
        "GET": UserGroupAuthorizationScheme.Perms.USER_GROUP_VIEW,
    }

    def get_queryset(self):
        return self.get_requested_model_queryset()


class AssignedPermViewSet(AuthorizationViewSetMixin, ModelViewSet):
    serializer_class = AssignedPermSerializer
    lookup_field = "pk"
    lookup_url_kwarg = "privilege_id"

    authorization_solver = AuthorizationSolver

    perms_map = {
        "GET": AssignedPermAuthorizationScheme.Perms.AUTHORIZATION_VIEW,
        "POST": AssignedPermAuthorizationScheme.Perms.AUTHORIZATION_ADD,
        "DELETE": AssignedPermAuthorizationScheme.Perms.AUTHORIZATION_DELETE,
    }

    def get_queryset(self):
        return self.get_requested_model_queryset()

    # def get_authorization_relation(self):
    #     if self.request.method == "POST":
    #         return "root"
    #
    #     return super().get_authorization_relation()

    def get_authorization_context_extra(self, *args, **kwargs) -> dict:
        if self.request.method == "POST":
            return self.get_serializer().to_internal_value(self.request.data)

        return super().get_authorization_context_extra(*args, **kwargs)
