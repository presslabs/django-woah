from rest_framework import status
from rest_framework.reverse import reverse_lazy

from django_woah.models import (
    Membership,
    UserGroup,
    AssignedPerm,
    create_user_membership_to_account,
    get_or_create_root_user_group,
)
from .authorization import IssueAuthorizationScheme
from .models import Issue, Project


def test_list_issues_empty(api_client, unrelated_account, unrelated_organization):
    Issue.objects.create(
        owner=unrelated_organization,
        author=unrelated_account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=unrelated_organization, created_by=unrelated_account, name="Project"
        ),
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == []


def test_list_issues_as_owner_no_membership(api_client, account, unrelated_organization):
    Issue.objects.create(
        owner=unrelated_organization,
        author=account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=unrelated_organization, created_by=account, name="Project"
        ),
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == []


def test_list_issues_as_project_owner(api_client, account):
    account.is_organization = True
    account.save()

    org_users = UserGroup.objects.create(kind=UserGroup.KINDS.ROOT, owner=account)
    Membership.objects.create(user=account, user_group=org_users, root_user_group=org_users)

    issue = Issue.objects.create(
        owner=account,
        author=account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(owner=account, created_by=account, name="Project"),
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/issues/{issue.id}",
            "owner": {
                "email": account.email,
                "username": account.username,
                "name": account.name,
                "url": f"http://testserver/api/accounts/{account.id}",
                "is_organization": True,
            },
            "title": "Issue #1",
            "content": "Help I can't install the deps!!!11",
        }
    ]


def test_list_issues_as_authorized_org_member(api_client, account, unrelated_account):
    unrelated_account.is_organization = True
    unrelated_account.save()

    org_users = UserGroup.objects.create(kind=UserGroup.KINDS.ROOT, owner=unrelated_account)

    Membership.objects.create(user=account, user_group=org_users, root_user_group=org_users)

    issue = Issue.objects.create(
        owner=unrelated_account,
        author=unrelated_account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=unrelated_account, created_by=unrelated_account, name="Project"
        ),
    )

    AssignedPerm.objects.create(
        user_group=org_users,
        owner=unrelated_account,
        perm=IssueAuthorizationScheme.Perms.ISSUE_VIEW,
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/issues/{issue.id}",
            "owner": {
                "email": unrelated_account.email,
                "username": unrelated_account.username,
                "name": unrelated_account.name,
                "url": f"http://testserver/api/accounts/{unrelated_account.id}",
                "is_organization": True,
            },
            "title": "Issue #1",
            "content": "Help I can't install the deps!!!11",
        }
    ]


def test_list_issues_as_org_member_with_explicit_issue_view_authorization_for_all_members(
    api_client, account, unrelated_account
):
    unrelated_account.is_organization = True
    unrelated_account.save()

    org_users = UserGroup.objects.create(kind=UserGroup.KINDS.ROOT, owner=unrelated_account)

    Membership.objects.create(user=account, user_group=org_users, root_user_group=org_users)

    issue = Issue.objects.create(
        owner=unrelated_account,
        author=unrelated_account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=unrelated_account, created_by=unrelated_account, name="Project"
        ),
    )

    AssignedPerm.objects.create(
        user_group=org_users,
        owner=unrelated_account,
        perm=IssueAuthorizationScheme.Perms.ISSUE_VIEW,
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/issues/{issue.id}",
            "owner": {
                "email": unrelated_account.email,
                "username": unrelated_account.username,
                "name": unrelated_account.name,
                "url": f"http://testserver/api/accounts/{unrelated_account.id}",
                "is_organization": True,
            },
            "title": "Issue #1",
            "content": "Help I can't install the deps!!!11",
        }
    ]


def test_list_issues_as_org_member_and_issue_ownership(api_client, account, unrelated_account):
    unrelated_account.is_organization = True
    unrelated_account.save()

    org_users = UserGroup.objects.create(kind=UserGroup.KINDS.ROOT, owner=unrelated_account)

    Membership.objects.create(user=account, user_group=org_users, root_user_group=org_users)

    issue = Issue.objects.create(
        owner=unrelated_account,
        author=account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=unrelated_account, created_by=unrelated_account, name="Project"
        ),
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/issues/{issue.id}",
            "owner": {
                "email": unrelated_account.email,
                "username": unrelated_account.username,
                "name": unrelated_account.name,
                "url": f"http://testserver/api/accounts/{unrelated_account.id}",
                "is_organization": True,
            },
            "title": "Issue #1",
            "content": "Help I can't install the deps!!!11",
        }
    ]


def test_issue_get_accounts_authorized_to_view(account, unrelated_account, organization):
    issue = Issue.objects.create(
        owner=organization,
        author=account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(owner=organization, created_by=organization, name="Project"),
    )

    assert list(issue.get_authorized_accounts(IssueAuthorizationScheme.Perms.ISSUE_VIEW)) == [
        account
    ]

    unrelated_account_membership, _ = create_user_membership_to_account(
        unrelated_account, organization
    )

    assert list(issue.get_authorized_accounts(IssueAuthorizationScheme.Perms.ISSUE_VIEW)) == [
        account,
        unrelated_account,
    ]

    account_membership = Membership.objects.get(
        user=account, user_group=get_or_create_root_user_group(organization)
    )
    account_membership.delete()

    assert list(issue.get_authorized_accounts(IssueAuthorizationScheme.Perms.ISSUE_VIEW)) == [
        unrelated_account
    ]

    unrelated_account_membership.delete()

    assert list(issue.get_authorized_accounts(IssueAuthorizationScheme.Perms.ISSUE_VIEW)) == []
