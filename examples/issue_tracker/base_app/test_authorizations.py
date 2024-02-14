from rest_framework import status
from rest_framework.reverse import reverse_lazy

from django_woah.models import (
    UserGroup,
    AssignedPerm,
    add_user_to_user_group,
)
from .authorization import (
    MembershipAuthorizationScheme,
    AssignedPermAuthorizationScheme,
    AuthorizationSolver,
)


def test_list_assigned_perms(api_client, account, organization):
    root_org_user_group = UserGroup.objects.get(
        kind=UserGroup.KINDS.ROOT, owner=organization
    )
    account_user_group = UserGroup.objects.get(
        related_user=account, root=root_org_user_group
    )

    assigned_perm = AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
    )

    response = api_client.get(reverse_lazy("assigned-perm-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/assigned_perms/{assigned_perm.pk}",
            "perm": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            "user_group": f"http://testserver/api/user_groups/{account_user_group.id}",
            "resource": None,
        },
    ]


def test_add_assigned_perm_actor_cant_give_rights_they_dont_have(
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

    add_assigned_perm = AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=AssignedPermAuthorizationScheme.Perms.AUTHORIZATION_ADD,
    )

    assert not AuthorizationSolver.get_authorized_resources_queryset(
        context=AuthorizationSolver.get_context(
            perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            actor=account,
            resource=root_org_user_group,
        ),
    ).exists()

    response = api_client.post(
        reverse_lazy("assigned-perm-list"),
        data={
            "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.id}",
            "perm": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            "resource": f"http://testserver/api/user_groups/{root_org_user_group.id}",
        },
    )

    assert add_assigned_perm == AssignedPerm.objects.last()

    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_add_assigned_perm_when_assigned_perm_is_given_on_user_group(
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

    AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=AssignedPermAuthorizationScheme.Perms.AUTHORIZATION_ADD,
    )

    AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
    )

    assert AuthorizationSolver.get_authorized_resources_queryset(
        context=AuthorizationSolver.get_context(
            perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            actor=account,
            resource=root_org_user_group,
        ),
    ).exists()

    response = api_client.post(
        reverse_lazy("assigned-perm-list"),
        data={
            "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.id}",
            "perm": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
            "resource": f"http://testserver/api/user_groups/{root_org_user_group.id}",
        },
    )

    created_assigned_perm = AssignedPerm.objects.last()

    assert response.status_code == status.HTTP_201_CREATED
    assert response.data == {
        "url": f"http://testserver/api/assigned_perms/{created_assigned_perm.pk}",
        "perm": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
        "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.id}",
        "resource": f"http://testserver/api/user_groups/{root_org_user_group.id}",
    }


# def test_add_assigned_perm_as_root_account_owner(
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
#     AssignedPerm.objects.create(
#         user_group=account_user_group,
#         owner=organization,
#         perm=AccountAuthorizationScheme.Roles.OWNER,
#         resource=root_org_user_group,
#     )
#
#     AssignedPerm.objects.create(
#         user_group=account_user_group,
#         owner=organization,
#         perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#     )
#
#     assert AuthorizationSolver.get_authorized_resources_queryset(
#         context=AuthorizationSolver.get_context(
#             perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#             actor=account,
#             resource=root_org_user_group,
#         ),
#     ).exists()
#
#     response = api_client.post(
#         reverse_lazy("assigned-perm-list"),
#         data={
#             "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.id}",
#             "perm": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#             "resource": f"http://testserver/api/user_groups/{root_org_user_group.id}",
#         },
#     )
#
#     created_assigned_perm = AssignedPerm.objects.last()
#
#     assert response.status_code == status.HTTP_201_CREATED, response.data
#     assert response.data == {
#         "url": f"http://testserver/api/assigned_perms/{created_assigned_perm.pk}",
#         "perm": MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
#         "user_group": f"http://testserver/api/user_groups/{unrelated_account_user_group.id}",
#         "resource": f"http://testserver/api/user_groups/{root_org_user_group.id}",
#     }
