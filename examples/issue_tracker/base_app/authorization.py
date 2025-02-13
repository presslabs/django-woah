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

from django.db.models import Q

from django_woah.authorization import (
    ModelAuthorizationScheme,
    Context,
    HasSameResourcePerms,
    HasRelatedResourcePerms,
    HasRootMembership,
    AuthorizationSolver,
    QCondition,
    Condition,
    HasUnrelatedResourcePerms,
    PermEnum,
    IndirectPerms,
    ConditionalPerms,
    TransitiveFromRelationPerms,
)
from django_woah.models import Membership, UserGroup, AssignedPerm
from .models import Issue, Project, Account


class ProjectAuthorizationScheme(ModelAuthorizationScheme):
    model = Project
    owner_relation = "owner"

    class Roles(PermEnum):
        PROJECT_OWNER = "project:owner"

    @classmethod
    def get_borrowed_perms(cls) -> list[PermEnum]:
        return IssueAuthorizationScheme.get_scheme_perms()

    def get_implicit_conditions(self, context: Context) -> list[Condition]:
        return [
            HasRootMembership(actor=context.actor),
        ]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        relation=self.owner_relation,
                        perms=[AccountAuthorizationScheme.Roles.OWNER],
                    )
                ],
                receives_perms=[self.Roles.PROJECT_OWNER],
            )
        ]


class IssueAuthorizationScheme(ModelAuthorizationScheme):
    model = Issue
    owner_relation = "owner"

    class Perms(PermEnum):
        ISSUE_VIEW = "issue:issue_view"
        ISSUE_CREATE = "issue:issue_create"
        ISSUE_EDIT = "issue:issue_edit"
        ISSUE_CLOSE = "issue:issue_close"
        ISSUE_DELETE = "issue:issue_delete"

    class Roles(PermEnum):
        ISSUE_MANAGER = "issue:issue_manager"

    def get_implicit_conditions(self, context: Context) -> list[Condition]:
        return [
            HasRootMembership(actor=context.actor),
        ]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            TransitiveFromRelationPerms(
                relation="project",
            ),
            ConditionalPerms(
                conditions=[
                    HasSameResourcePerms(perms=[self.Roles.ISSUE_MANAGER]),
                ],
                receives_perms=[
                    self.Perms.ISSUE_VIEW,
                    self.Perms.ISSUE_CREATE,
                    self.Perms.ISSUE_EDIT,
                    self.Perms.ISSUE_CLOSE,
                    self.Perms.ISSUE_DELETE,
                ],
            ),
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        relation="project",
                        perms=[ProjectAuthorizationScheme.Roles.PROJECT_OWNER],
                    )
                    | QCondition(Q(author=context.actor)),
                ],
                receives_perms=[self.Roles.ISSUE_MANAGER],
            ),
            ConditionalPerms(
                conditions=[HasRootMembership(actor=context.actor)],
                receives_perms=[self.Perms.ISSUE_VIEW],
            ),
        ]


class MembershipAuthorizationScheme(ModelAuthorizationScheme):
    model = Membership
    owner_relation = "root_user_group"

    class Perms(PermEnum):
        MEMBERSHIP_VIEW = "membership:membership_view"
        MEMBERSHIP_CREATE = "membership:membership_create"
        MEMBERSHIP_DELETE = "membership:membership_delete"
        MEMBERSHIP_EDIT = "membership:membership_edit"

    class Roles(PermEnum):
        MEMBERSHIP_MANAGER = "membership:membership_manager"

    def get_implicit_conditions(self, context: Context) -> list[Condition]:
        return [HasRootMembership(actor=context.actor)]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            TransitiveFromRelationPerms(  # TODO: check if this wrongly implies that permissions apply to relation by
                relation="user_group",
            ),
            ConditionalPerms(
                conditions=[HasRootMembership(actor=context.actor)],
                receives_perms=[self.Perms.MEMBERSHIP_VIEW],
            ),
            ConditionalPerms(
                conditions=[QCondition(Q(user=context.actor))],
                receives_perms=[self.Perms.MEMBERSHIP_DELETE],
            ),
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        relation=self.owner_relation,
                        perms=[AccountAuthorizationScheme.Roles.OWNER],
                    ),
                ],
                receives_perms=[self.Roles.MEMBERSHIP_MANAGER],
            ),
        ]


class AccountAuthorizationScheme(ModelAuthorizationScheme):
    model = Account
    owner_relation = "*"

    class Perms(PermEnum):
        ACCOUNT_VIEW = "account:account_view"
        ACCOUNT_EDIT = "account:account_edit"
        ACCOUNT_DELETE = "account:account_delete"

    class Roles(PermEnum):
        OWNER = "account:account_owner"

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[HasSameResourcePerms(perms=[self.Roles.OWNER])],
                receives_perms=[
                    self.Perms.ACCOUNT_VIEW,
                    self.Perms.ACCOUNT_EDIT,
                    self.Perms.ACCOUNT_DELETE,
                ],
            ),
            ConditionalPerms(
                conditions=[QCondition(Q(pk=context.actor.pk))],
                receives_perms=[self.Roles.OWNER],
            ),
            ConditionalPerms(
                conditions=[
                    HasRootMembership(
                        actor=context.actor,
                        is_outside_collaborator=None,
                    )
                ],
                receives_perms=[self.Perms.ACCOUNT_VIEW],
            ),
        ]


class UserGroupAuthorizationScheme(ModelAuthorizationScheme):
    model = UserGroup
    owner_relation = "owner"

    class Perms(PermEnum):
        USER_GROUP_VIEW = "user_group:user_group_view"
        USER_GROUP_EDIT = "user_group:user_group_edit"
        USER_GROUP_DELETE = "user_group:user_group_delete"

    # def get_implicit_conditions(
    #     self, context: Context
    # ) -> list[Condition]:
    #     return [
    #         HasRootMembership( actor=context.actor),
    #         QCondition(Q(kind=UserGroup.KINDS.ROOT)),
    #     ]

    @classmethod
    def get_borrowed_perms(cls) -> list[PermEnum]:
        return MembershipAuthorizationScheme.get_scheme_perms()

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[
                    (
                        QCondition(Q(kind=UserGroup.KINDS.ROOT))
                        & HasRelatedResourcePerms(
                            relation="related_user",
                            perms=[AccountAuthorizationScheme.Roles.OWNER],
                        )
                    )
                    | (
                        HasRelatedResourcePerms(
                            relation="root__related_user",
                            perms=[AccountAuthorizationScheme.Roles.OWNER],
                        )
                    )
                ],
                receives_perms=self.Perms.values(),
            )
        ]


class AssignedPermAuthorizationScheme(ModelAuthorizationScheme):
    model = AssignedPerm
    owner_relation = "owner"

    class Perms(PermEnum):
        AUTHORIZATION_VIEW = "authorization:authorization_view"
        AUTHORIZATION_ADD = "authorization:authorization_add"
        AUTHORIZATION_DELETE = "authorization:authorization_delete"

    def get_implicit_conditions(self, context: Context) -> list:
        if context.perm in [self.Perms.AUTHORIZATION_ADD]:
            return [
                HasUnrelatedResourcePerms(
                    resource=context.extra["resource"],
                    perms=[context.extra["perm"]],
                )
            ]

        return [HasRootMembership(actor=context.actor)]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[QCondition(Q(user_group__memberships__user=context.actor))],
                receives_perms=[self.Perms.AUTHORIZATION_VIEW],
            ),
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        relation="owner",
                        perms=[AccountAuthorizationScheme.Roles.OWNER],
                    )
                ],
                receives_perms=self.Perms.values(),
            ),
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        relation="user_group",
                        perms=[self.Perms.AUTHORIZATION_ADD],
                    )
                ],
                receives_perms=[self.Perms.AUTHORIZATION_ADD],
            ),
        ]


AuthorizationSolver = AuthorizationSolver(
    authorization_schemes=[
        IssueAuthorizationScheme,
        ProjectAuthorizationScheme,
        MembershipAuthorizationScheme,
        AccountAuthorizationScheme,
        UserGroupAuthorizationScheme,
        AssignedPermAuthorizationScheme,
    ]
)
