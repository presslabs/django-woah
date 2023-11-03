from django.db.models import Q
from rest_framework import status
from rest_framework.reverse import reverse_lazy

from django_woah.authorization import Context
from django_woah.models import (
    Membership,
    UserGroup,
    Authorization,
    add_user_to_user_group,
)
from .authorization import (
    IssueAuthorizationScheme,
    MembershipAuthorizationScheme,
    AuthorizationAuthorizationScheme,
    AuthorizationSolver,
    AccountAuthorizationScheme,
)
from .models import Issue, Project, Account


def test_list_authorizations(api_client, account, organization):
    root_org_user_group = UserGroup.objects.get(
        kind=UserGroup.KINDS.ROOT, owner=organization
    )
    account_user_group = UserGroup.objects.get(
        related_user=account, root=root_org_user_group
    )

    authorization = Authorization.objects.create(
        user_group=account_user_group,
        root=root_org_user_group,
        role=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
    )

    response = api_client.get(reverse_lazy("authorization-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/authorizations/{authorization.pk}",
            "role": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            "user_group": f"http://testserver/api/user_groups/{account_user_group.uuid}",
            "resource": None,
        },
    ]


def test_add_authorization_actor_cant_give_rights_they_dont_have(
    api_client, account, organization, unrelated_account
):
    root_org_user_group = UserGroup.objects.get(
        kind=UserGroup.KINDS.ROOT, owner=organization
    )
    print("root_org_user_group!!!", root_org_user_group)

    account_user_group = UserGroup.objects.get(
        related_user=account, root=root_org_user_group
    )

    _, unrelated_account_user_group = add_user_to_user_group(
        user=unrelated_account, user_group=root_org_user_group
    )

    add_authorization = Authorization.objects.create(
        user_group=account_user_group,
        root=root_org_user_group,
        role=AuthorizationAuthorizationScheme.Perms.AUTHORIZATION_ADD,
    )

    assert not AuthorizationSolver.get_authorized_resources_queryset(
        perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
        context=AuthorizationSolver.get_context(
            # TODO DRY perm
            perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            actor=account,
            resource=root_org_user_group,
        ),
    ).exists()

    response = api_client.post(
        reverse_lazy("authorization-list"),
        data={
            "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.uuid}",
            "role": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            "resource": f"http://testserver/api/user_groups/{root_org_user_group.uuid}",
        },
    )

    assert add_authorization == Authorization.objects.last()

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_add_authorization_when_authorization_is_given_on_user_group(
    api_client, account, organization, unrelated_account
):
    root_org_user_group = UserGroup.objects.get(
        kind=UserGroup.KINDS.ROOT, owner=organization
    )
    account_user_group = UserGroup.objects.get(
        related_user=account, root=root_org_user_group
    )

    _, unrelated_account_user_group = add_user_to_user_group(
        user=unrelated_account, user_group=root_org_user_group
    )

    Authorization.objects.create(
        user_group=account_user_group,
        root=root_org_user_group,
        role=AuthorizationAuthorizationScheme.Perms.AUTHORIZATION_ADD,
    )

    Authorization.objects.create(
        user_group=account_user_group,
        root=root_org_user_group,
        role=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
    )

    assert AuthorizationSolver.get_authorized_resources_queryset(
        perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
        context=AuthorizationSolver.get_context(
            # TODO DRY perm
            perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            actor=account,
            resource=root_org_user_group,
        ),
    ).exists()

    response = api_client.post(
        reverse_lazy("authorization-list"),
        data={
            "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.uuid}",
            "role": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            "resource": f"http://testserver/api/user_groups/{root_org_user_group.uuid}",
        },
    )

    created_authorization = Authorization.objects.last()

    assert response.status_code == status.HTTP_201_CREATED
    assert response.data == {
        "url": f"http://testserver/api/authorizations/{created_authorization.pk}",
        "role": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
        "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.uuid}",
        "resource": f"http://testserver/api/user_groups/{root_org_user_group.uuid}",
    }


# def test_add_authorization_as_root_account_owner(
#     api_client, account, organization, unrelated_account
# ):
#     root_org_user_group = UserGroup.objects.get(
#         kind=UserGroup.KINDS.ROOT, owner=organization
#     )
#     account_user_group = UserGroup.objects.get(
#         owner=account, root=root_org_user_group
#     )
#
#     _, unrelated_account_user_group = add_user_to_user_group(
#         user=unrelated_account, user_group=organization.related_user_groups.first()
#     )
#
#     Authorization.objects.create(
#         user_group=account_user_group,
#         root=root_org_user_group,
#         role=AccountAuthorizationScheme.Roles.OWNER,
#         resource=root_org_user_group,
#     )
#
#     Authorization.objects.create(
#         user_group=account_user_group,
#         root=root_org_user_group,
#         role=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#     )
#
#     assert AuthorizationSolver.get_authorized_resources_queryset(
#         perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#         context=AuthorizationSolver.get_context(
#             # TODO DRY perm
#             perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#             actor=account,
#             resource=root_org_user_group,
#         ),
#     ).exists()
#
#     response = api_client.post(
#         reverse_lazy("authorization-list"),
#         data={
#             "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.uuid}",
#             "role": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#             "resource": f"http://testserver/api/user_groups/{root_org_user_group.uuid}",
#         },
#     )
#
#     created_authorization = Authorization.objects.last()
#
#     print(response.data)
#     assert response.status_code == status.HTTP_201_CREATED
#     assert response.data == {
#         "url": f"http://testserver/api/authorizations/{created_authorization.pk}",
#         "role": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#         "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.uuid}",
#         "resource": f"http://testserver/api/user_groups/{root_org_user_group.uuid}",
#     }
