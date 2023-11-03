from django.db.models import Q

from django_woah.authorization import (
    AuthorizationScheme,
    Context,
    IndirectPerms,
    HasSameResourcePerms,
    HasRelatedResourcePerms,
    HasMembership,
    AuthorizationSolver,
    ConditionalPerms,
    TransitiveFromRelationPerms,
    QCondition,
    PermEnum,
    Condition,
    HasUnrelatedResourcePerms,
)
from django_woah.models import Membership, UserGroup, Authorization
from .models import Issue, Project, Account


class ProjectAuthorizationScheme(AuthorizationScheme):
    model = Project
    owner_relation = "owner"

    class Perms(PermEnum):
        PROJECT_OWNER = "project:owner"

    def get_implicit_conditions(
        self, perm: PermEnum, context: Context
    ) -> list[Condition]:
        return [HasMembership(scheme=self, actor=context.actor)]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        scheme=self,
                        relation=self.owner_relation,
                        perms=[AccountAuthorizationScheme.Roles.OWNER],
                    )
                ],
                receives_perms=[self.Perms.PROJECT_OWNER],
            )
        ]


class IssueAuthorizationScheme(AuthorizationScheme):
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

    def get_implicit_conditions(
        self, perm: PermEnum, context: Context
    ) -> list[Condition]:
        return [HasMembership(scheme=self, actor=context.actor)]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            TransitiveFromRelationPerms(
                scheme=self,
                relation="project",
            ),
            ConditionalPerms(
                conditions=[
                    HasSameResourcePerms(self, perms=[self.Roles.ISSUE_MANAGER]),
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
                        scheme=self,
                        relation="project",
                        perms=[ProjectAuthorizationScheme.Perms.PROJECT_OWNER],
                    )
                ],
                receives_perms=[self.Roles.ISSUE_MANAGER],
            ),
            ConditionalPerms(
                conditions=[
                    QCondition(Q(author=context.actor)),
                ],
                receives_perms=[self.Perms.ISSUE_VIEW],
            ),
        ]


class MembershipAuthorizationScheme(AuthorizationScheme):
    model = Membership
    # TODO: would it hurt to have this point to the root_user_group__related_user or even replace
    # the that with a direct relation to the Account (think performance vs DX)
    owner_relation = "root_user_group"

    class Perms(PermEnum):
        MEMBERSHIP_VIEW = "membership:membership_view"
        MEMBERSHIP_CREATE = "membership:membership_create"
        MEMBERSHIP_DELETE = "membership:membership_delete"
        MEMBERSHIP_EDIT = "membership:membership_edit"

    class Roles(PermEnum):
        MEMBERSHIP_MANAGER = "membership:membership_manager"

    def get_implicit_conditions(
        self, perm: PermEnum, context: Context
    ) -> list[Condition]:
        return [HasMembership(scheme=self, actor=context.actor)]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            TransitiveFromRelationPerms(  # TODO: this wrongly implies that permissions apply to relation by
                scheme=self,
                relation="user_group",
            ),
            ConditionalPerms(
                receives_perms=[
                    self.Perms.MEMBERSHIP_VIEW,
                ],
                conditions=[HasMembership(scheme=self, actor=context.actor)],
            ),
            ConditionalPerms(
                receives_perms=[
                    self.Perms.MEMBERSHIP_DELETE,
                ],
                conditions=[QCondition(Q(user=context.actor))],
            ),
            ConditionalPerms(
                receives_perms=[
                    self.Roles.MEMBERSHIP_MANAGER,
                ],
                conditions=[
                    HasRelatedResourcePerms(
                        scheme=self,
                        relation=self.owner_relation,
                        perms=[AccountAuthorizationScheme.Roles.OWNER],
                    ),
                ],
            ),
        ]


class AccountAuthorizationScheme(AuthorizationScheme):
    model = Account
    owner_relation = "*"  # This should be more explicit

    class Perms(PermEnum):
        ACCOUNT_VIEW = "account:account_view"
        ACCOUNT_EDIT = "account:account_edit"
        ACCOUNT_DELETE = "account:account_delete"

    class Roles(PermEnum):
        OWNER = "account:account_owner"

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[
                    HasSameResourcePerms(scheme=self, perms=[self.Roles.OWNER])
                ],
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
            # ConditionalPerms(
            #     conditions=[
            #         HasRelatedResourcePerms(
            #             scheme=self,
            #             relation="user_groups",
            #             perms=[RootUserGroupAuthorizationScheme.Roles.ACCOUNT_OWNER],
            #         ),
            #         QCondition(Q(user_groups__kind=UserGroup.KINDS.ROOT)),
            #     ],
            #     receives_perms=[self.Roles.OWNER],
            # ),
            ConditionalPerms(
                conditions=[
                    HasMembership(
                        scheme=self,
                        actor=context.actor,
                        include_outside_collaborators=None,
                    )
                ],
                receives_perms=[self.Perms.ACCOUNT_VIEW],
            ),
        ]


class RootUserGroupAuthorizationScheme(AuthorizationScheme):
    model = UserGroup
    owner_relation = "owner"

    # Replacing the owner_relation * with a constant FK to the owner User would get rid of the problem below
    # But are there use cases where you want to separate the User from an Organization as different
    # models, and the RootUserGroup would unify these?

    # owner_relation = "*"
    # TODO: this is actually not correct as most groups have root as owner
    # Use implicit conditions to split logic between root and other kind of usergroups (overlapping should also be fine)
    # The get_scheme_for_model will become get_schemes_for_model and their respective Qs will be OR-ed (|)
    # This should allow for finer separation of business logic / flows too
    # For example adding a user to an organization might be different from adding a user to a team
    # And adding or removing users from single USER "groups" should be disallowed from authorizations (if this is
    #   the right approach is debatable though).

    # def get_owner_relations(self):
    #     return [
    #         # TODO: should this actually be related_user
    #         Relation(traversal="*", conditions=[QCondition(kind=UserGroup.KINDS.ROOT)]),
    #         # TODO: should this actually be root__related_user
    #         Relation(
    #             traversal="root", conditions=[QCondition(kind__ne=UserGroup.KINDS.ROOT)]
    #         ),
    #     ]

    class Perms(PermEnum):
        ACCOUNT_VIEW = "root_user_group:root_user_group_view"
        ACCOUNT_EDIT = "root_user_group:root_user_group_edit"
        ACCOUNT_DELETE = "root_user_group:root_user_group_delete"

    # def get_implicit_conditions(
    #     self, perm: PermEnum, context: Context
    # ) -> list[Condition]:
    #     return [
    #         HasMembership(scheme=self, actor=context.actor),
    #         QCondition(Q(kind=UserGroup.KINDS.ROOT)),
    #     ]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[
                    (
                        QCondition(Q(kind=UserGroup.KINDS.ROOT))
                        & HasRelatedResourcePerms(
                            scheme=self,
                            relation="related_user",
                            perms=[AccountAuthorizationScheme.Roles.OWNER],
                        )
                    )
                    | (
                        HasRelatedResourcePerms(
                            scheme=self,
                            relation="root__related_user",
                            perms=[AccountAuthorizationScheme.Roles.OWNER],
                        )
                    )
                ],
                receives_perms=self.Perms.values(),
            )
        ]


class AuthorizationAuthorizationScheme(AuthorizationScheme):
    model = Authorization
    owner_relation = "root__owner"

    class Perms(PermEnum):
        AUTHORIZATION_VIEW = "authorization:authorization_view"
        # TODO: What to do with these type of permissions that are not directly attributed, because they cannot be
        # filtered on the resource (since the resource doesn't exist in the first place)
        # 1. Request-level authorization with yes/no response
        #    - But how does the context get specified, how does the transitive perms relations get shoved into the
        #      context?
        AUTHORIZATION_ADD = "authorization:authorization_add"
        AUTHORIZATION_DELETE = "authorization:authorization_delete"

    def get_implicit_conditions(self, perm: PermEnum, context: Context) -> list:
        if perm in [self.Perms.AUTHORIZATION_ADD]:
            print("CONTEXT EXTRA!!!", context.extra)

            return [
                HasUnrelatedResourcePerms(
                    scheme=self,
                    resource=context.extra["resource"],
                    perms=[context.extra["role"]],
                )
            ]

            # TODO: so we need an "unrelated" resource HasResourcePerms mode where a contenttype, and ID (or even resource)
            # can be passed, let's say from context.extra
            # Thing is, because it's unrelated, this Q should be top-level, and how do we specify that?
            # 1. A solution although unclear, would be to have a Tree of conditions and what perms they give
            #   And only at the end walk that tree and compute the Qs.
            #   This could prove useful for other use-cases?
            # ~2~. Set an attribute on the Q stating it should be top-level, and prefixing should not happen for
            #   those types of Qs. Thing is, after one nesting, that information would probably be lost
            #   because of | and & operations with other Qs.
            # 3. Move perm somewhere in context in relation to resources. What queryset does the
            #   AuthorizationSolver return in case additional Permissions are checked for other (types of) resources?
            #   Also this moves the logic that decides what other permissions are needed closer to user implementation
            #   and makes it less declarative. Moving this extra permissions check in the AuthorizationSolver could be a
            #   thing though.
            #   What about the case where there are 2 resources with equal importance in the action? Like
            #   syncing between two resources. One requires read, one requires write, maybe an extra condition
            #   that they belong to the same organization/project. In this specific situation, the resource would be a
            #   third which would be a SyncRequest. So maybe it's a decent compromise to always have to specify a main
            #   resource that is acted on, and then some extras. Also this is a case where a bool result makes more sense
            #   than a queryset result, since the perm for the SyncRequest.CREATE would probably be done on the project
            #   and or org.
            #   3.1 Maybe perms should be tied to Contexts. For example for Membership.Create if you receive the
            #   UserGroup in the context, you could say, require HasResourcePerms(context.Membership.UserGroup, perm=Membership.Create) for it.
            #   But how does this help bro?
            #   4. Conditions should be markable as separate (at least for the resources Q, authorizations should still be bulked)
            #   These separate conditions are to be tied to the root context, and executed before executing the main resources Q.
            #   The result of the evaluation will be converted into a true or false Q.
            #   4.1 But what if the top-level evaluation is a different method, and then the arbitrary result of that is
            #   to be used in the condition's main resources_q? Some prefetching could be done this way.

        return [HasMembership(scheme=self, actor=context.actor)]

    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
        return [
            ConditionalPerms(
                conditions=[QCondition(Q(user_group__memberships__user=context.actor))],
                receives_perms=[
                    self.Perms.AUTHORIZATION_VIEW,
                ],
            ),
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        scheme=self,
                        # TODO: link the root from the context to this root and query the relation
                        relation="root__owner",
                        perms=[AccountAuthorizationScheme.Roles.OWNER],
                    )
                ],
                receives_perms=self.Perms.values(),
            ),
            ConditionalPerms(
                conditions=[
                    HasRelatedResourcePerms(
                        scheme=self,
                        # TODO: link the root from the context to this root and query the relation
                        relation="user_group",
                        perms=[self.Perms.AUTHORIZATION_ADD],
                    )
                ],
                receives_perms=[self.Perms.AUTHORIZATION_ADD],
            ),
        ]


# class NonRootUserGroupAuthorizationScheme(AuthorizationScheme):
#     model = UserGroup
#     owner_relation = "root"
#
#     def get_implicit_conditions(
#         self, perm: PermEnum, context: Context
#     ) -> list[Condition]:
#         return super().get_implicit_conditions(perm, context) + [
#             QCondition(Q(kind__ne=UserGroup.KINDS.ROOT))
#         ]
#
#     class Perms(PermEnum):
#         USER_GROUP_VIEW = "user_group:account_view"


AuthorizationSolver = AuthorizationSolver(
    authorization_schemes=[
        IssueAuthorizationScheme,
        ProjectAuthorizationScheme,
        MembershipAuthorizationScheme,
        AccountAuthorizationScheme,
        RootUserGroupAuthorizationScheme,
        AuthorizationAuthorizationScheme,
    ]
)
