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
    lookup_field = "id"
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
    lookup_field = "id"
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
    lookup_field = "id"
    lookup_url_kwarg = "membership_id"

    authorization_solver = AuthorizationSolver

    perms_map = {
        "GET": MembershipAuthorizationScheme.Perms.MEMBERSHIP_VIEW,
        "POST": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
    }

    def get_queryset(self):
        return self.get_requested_model_queryset()


class UserGroupViewSet(AuthorizationViewSetMixin, ModelViewSet):
    serializer_class = UserGroupSerializer
    lookup_field = "id"
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

    def get_authorization_context_extra(self, *args, **kwargs) -> dict:
        if self.request.method == "POST":
            return self.get_serializer().to_internal_value(self.request.data)

        return super().get_authorization_context_extra(*args, **kwargs)
