from django.db.models import Q
from rest_framework import status
from rest_framework.reverse import reverse_lazy

from django_woah.models import (
    Membership,
    UserGroup,
    AssignedPerm,
    get_or_create_root_user_group_for_account,
)
from .authorization import (
    AccountAuthorizationScheme,
)
from .models import Account


def test_list_accounts_no_organizations(api_client, account, unrelated_account):
    response = api_client.get(reverse_lazy("account-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "email": account.email,
            "username": account.username,
            "name": account.name,
            "url": f"http://testserver/api/accounts/{account.uuid}",
            "is_organization": False,
        }
    ]


def test_list_accounts_with_no_access_to_organization(
    api_client, account, unrelated_account
):
    unrelated_account.is_organization = True
    unrelated_account.save()

    get_or_create_root_user_group_for_account(unrelated_account)

    response = api_client.get(reverse_lazy("account-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "email": account.email,
            "username": account.username,
            "name": account.name,
            "url": f"http://testserver/api/accounts/{account.uuid}",
            "is_organization": False,
        }
    ]


def test_list_accounts_which_have_access_to_organization(
    api_client, account, organization
):
    response = api_client.get(reverse_lazy("account-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "email": account.email,
            "username": account.username,
            "name": account.name,
            "url": f"http://testserver/api/accounts/{account.uuid}",
            "is_organization": False,
        },
        {
            "email": organization.email,
            "username": organization.username,
            "name": organization.name,
            "url": f"http://testserver/api/accounts/{organization.uuid}",
            "is_organization": True,
        },
    ]


def test_delete_account_self(api_client, account):
    response = api_client.delete(reverse_lazy("account-detail", args=[account.uuid]))

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not Account.objects.filter(uuid=account.uuid)


def test_delete_organization_as_owner(api_client, account, organization):
    root_org_user_group = UserGroup.objects.get(
        kind=UserGroup.KINDS.ROOT, owner=organization
    )
    account_user_group = UserGroup.objects.get(
        related_user=account, root=root_org_user_group
    )

    AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=AccountAuthorizationScheme.Roles.OWNER,
        resource=organization,
    )

    response = api_client.delete(
        reverse_lazy("account-detail", args=[organization.uuid])
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not Account.objects.filter(uuid=organization.uuid)


def test_delete_org_account_with_access_to_org_but_no_permission(
    api_client, organization
):
    response = api_client.delete(
        reverse_lazy("account-detail", args=[organization.uuid])
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.data == {
        "detail": "You do not have permission to perform this action."
    }


def test_delete_org_account_with_access_to_org_and_root_user_group_owner_role(
    api_client, account, organization, unrelated_organization
):
    root_org_user_group = UserGroup.objects.get(
        kind=UserGroup.KINDS.ROOT, owner=organization
    )
    account_user_group = UserGroup.objects.get(
        related_user=account, root=root_org_user_group
    )

    AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=AccountAuthorizationScheme.Roles.OWNER,
        resource=organization,
    )

    response = api_client.delete(
        reverse_lazy("account-detail", args=[organization.uuid])
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert not Account.objects.filter(uuid=organization.uuid)

    # Make sure related stuff like Memberships, UserGroups and Authorizations have been cascade deleted
    assert not AssignedPerm.objects.filter(owner=organization)
    assert not UserGroup.objects.filter(
        Q(root=root_org_user_group) | Q(owner=organization)
    )
    assert not Membership.objects.filter(root_user_group=root_org_user_group)

    assert Account.objects.filter(uuid=account.uuid)

    # Try again to delete the org
    response = api_client.delete(
        reverse_lazy("account-detail", args=[organization.uuid])
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.data == {
        "detail": "You do not have permission to perform this action."
    }

    # Try to delete the unrelated org
    response = api_client.delete(
        reverse_lazy("account-detail", args=[unrelated_organization.uuid])
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.data == {
        "detail": "You do not have permission to perform this action."
    }

    assert Account.objects.filter(uuid=unrelated_organization.uuid)


def test_delete_org_account_with_access_to_org_and_account_user_group_owner_role(
    api_client, account, organization, unrelated_organization
):
    # This would normally not be allowed... but say it happened, it should not result in Owner role per organization.

    root_org_user_group = UserGroup.objects.get(
        kind=UserGroup.KINDS.ROOT, owner=organization
    )
    account_user_group = UserGroup.objects.get(
        related_user=account, root=root_org_user_group
    )

    AssignedPerm.objects.create(
        user_group=account_user_group,
        owner=organization,
        perm=AccountAuthorizationScheme.Roles.OWNER,
        resource=account_user_group,
    )

    response = api_client.delete(
        reverse_lazy("account-detail", args=[organization.uuid])
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.data == {
        "detail": "You do not have permission to perform this action."
    }
