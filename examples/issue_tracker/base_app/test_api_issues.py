from rest_framework import status
from rest_framework.reverse import reverse_lazy

from django_woah.models import Membership, UserGroup, Authorization
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


def test_list_issues_as_owner_no_membership(
    api_client, account, unrelated_organization
):
    issue = Issue.objects.create(
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
    Membership.objects.create(
        user=account, user_group=org_users, root_user_group=org_users
    )

    issue = Issue.objects.create(
        owner=account,
        author=account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=account, created_by=account, name="Project"
        ),
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/issues/{issue.uuid}",
            "owner": {
                "email": account.email,
                "username": account.username,
                "name": account.name,
                "url": f"http://testserver/api/accounts/{account.uuid}",
                "is_organization": True,
            },
            "title": "Issue #1",
            "content": "Help I can't install the deps!!!11",
        }
    ]


def test_list_issues_as_authorized_org_member(api_client, account, unrelated_account):
    unrelated_account.is_organization = True
    unrelated_account.save()

    org_users = UserGroup.objects.create(
        kind=UserGroup.KINDS.ROOT, owner=unrelated_account
    )

    Membership.objects.create(
        user=account, user_group=org_users, root_user_group=org_users
    )

    issue = Issue.objects.create(
        owner=unrelated_account,
        author=unrelated_account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=unrelated_account, created_by=unrelated_account, name="Project"
        ),
    )

    Authorization.objects.create(
        user_group=org_users,
        root=org_users,
        role=IssueAuthorizationScheme.Perms.ISSUE_VIEW,
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/issues/{issue.uuid}",
            "owner": {
                "email": unrelated_account.email,
                "username": unrelated_account.username,
                "name": unrelated_account.name,
                "url": f"http://testserver/api/accounts/{unrelated_account.uuid}",
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

    org_users = UserGroup.objects.create(
        kind=UserGroup.KINDS.ROOT, owner=unrelated_account
    )

    Membership.objects.create(
        user=account, user_group=org_users, root_user_group=org_users
    )

    issue = Issue.objects.create(
        owner=unrelated_account,
        author=unrelated_account,
        title="Issue #1",
        content="Help I can't install the deps!!!11",
        project=Project.objects.create(
            owner=unrelated_account, created_by=unrelated_account, name="Project"
        ),
    )

    Authorization.objects.create(
        user_group=org_users,
        root=org_users,
        role=IssueAuthorizationScheme.Perms.ISSUE_VIEW,
    )

    response = api_client.get(reverse_lazy("issue-list"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data == [
        {
            "url": f"http://testserver/api/issues/{issue.uuid}",
            "owner": {
                "email": unrelated_account.email,
                "username": unrelated_account.username,
                "name": unrelated_account.name,
                "url": f"http://testserver/api/accounts/{unrelated_account.uuid}",
                "is_organization": True,
            },
            "title": "Issue #1",
            "content": "Help I can't install the deps!!!11",
        }
    ]


def test_list_issues_as_org_member_and_issue_ownership(
    api_client, account, unrelated_account
):
    unrelated_account.is_organization = True
    unrelated_account.save()

    org_users = UserGroup.objects.create(
        kind=UserGroup.KINDS.ROOT, owner=unrelated_account
    )

    Membership.objects.create(
        user=account, user_group=org_users, root_user_group=org_users
    )

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
            "url": f"http://testserver/api/issues/{issue.uuid}",
            "owner": {
                "email": unrelated_account.email,
                "username": unrelated_account.username,
                "name": unrelated_account.name,
                "url": f"http://testserver/api/accounts/{unrelated_account.uuid}",
                "is_organization": True,
            },
            "title": "Issue #1",
            "content": "Help I can't install the deps!!!11",
        }
    ]
