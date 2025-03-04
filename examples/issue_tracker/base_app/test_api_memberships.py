from rest_framework import status
from rest_framework.reverse import reverse_lazy

from django_woah.models import Membership, UserGroup, AssignedPerm
from .authorization import (
    MembershipAuthorizationScheme,
    AccountAuthorizationScheme,
)
from .models import Account


def test_list_memberships_as_org_member(api_client, account, organization):
    response = api_client.get(reverse_lazy("membership-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/memberships/{account.memberships.first().id}",
            "user_summary": {
                "email": account.email,
                "username": account.username,
                "name": account.name,
                "url": f"http://testserver/api/accounts/{account.id}",
                "is_organization": False,
            },
            "user_group": f"http://testserver/api/user_groups/{organization.owned_user_groups.get(kind=UserGroup.KINDS.ROOT).id}",
        },
        {
            "url": f"http://testserver/api/memberships/{account.memberships.last().id}",
            "user_summary": {
                "email": account.email,
                "username": account.username,
                "name": account.name,
                "url": f"http://testserver/api/accounts/{account.id}",
                "is_organization": False,
            },
            "user_group": f"http://testserver/api/user_groups/{account.related_user_groups.get().id}",
        },
    ]


def test_add_member_to_org_no_permission(api_client, account, organization):
    user_to_add = Account.objects.create(
        username="user_to_add", email="user_to_add@accounts.issues"
    )
    response = api_client.post(
        reverse_lazy("membership-list"),
        {
            "user": f"http://testserver/api/accounts/{user_to_add.id}",
            "user_group": f"http://testserver/api/user_groups/{organization.owned_user_groups.get(kind=UserGroup.KINDS.ROOT).id}",
        },
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert not Membership.objects.filter(user=user_to_add).exists()


def test_add_member_to_org_allowed(api_client, account, organization):
    root_org_user_group = UserGroup.objects.get(kind=UserGroup.KINDS.ROOT, owner=organization)
    account_user_group = UserGroup.objects.get(related_user=account, root=root_org_user_group)

    AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=AccountAuthorizationScheme.Roles.OWNER,
    )

    AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=MembershipAuthorizationScheme.Perms.MEMBERSHIP_CREATE,
    )

    user_to_add = Account.objects.create(
        username="user_to_add", email="user_to_add@accounts.issues"
    )
    response = api_client.post(
        reverse_lazy("membership-list"),
        {
            "user": f"http://testserver/api/accounts/{user_to_add.id}",
            "user_group": f"http://testserver/api/user_groups/{root_org_user_group.id}",
        },
    )

    assert response.status_code == status.HTTP_201_CREATED

    assert Membership.objects.filter(
        user=user_to_add,
        user_group=root_org_user_group,
        root_user_group=root_org_user_group,
    ).exists()

    assert Membership.objects.filter(
        user=user_to_add,
        root_user_group=root_org_user_group,
        user_group__related_user=user_to_add,
    ).exists()
