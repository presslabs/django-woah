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

import uuid6

from django.contrib.auth.base_user import AbstractBaseUser
from django.core.mail import send_mail
from django.db import models

from django_woah.authorization import Context, ModelAuthorizationScheme


class AuthorizationMixin:
    @property
    def authorization_scheme(self) -> ModelAuthorizationScheme:
        from .authorization import AuthorizationSolver

        return AuthorizationSolver.get_auth_scheme_for_model(self.__class__)

    def get_authorized_accounts(self, perm):
        from .authorization import AuthorizationSolver

        authorization_scheme = self.authorization_scheme

        if perm not in authorization_scheme.get_scheme_perms():
            raise ValueError(f"{perm} is not part of {authorization_scheme}'s perms.")

        return AuthorizationSolver.get_actors_queryset(
            AuthorizationSolver.get_context(
                resource=self, perm=perm, prefetch_memberships=True
            )
        )


class Account(AbstractBaseUser):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    username = models.CharField(max_length=64, unique=True)
    USERNAME_FIELD = "username"

    name = models.TextField(max_length=512)
    email = models.EmailField(unique=True)

    is_organization = models.BooleanField(default=False)

    def clean(self):
        if self.is_organization:
            if self.has_usable_password():
                self.set_unusable_password()

    def __str__(self):
        return f"{self.name} ({self.username})"


class Project(models.Model):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    owner = models.ForeignKey(
        Account, on_delete=models.CASCADE, related_name="owned_projects"
    )

    name = models.CharField(max_length=128)

    created_by = models.ForeignKey(
        Account,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_projects",
    )

    is_private = models.BooleanField(default=False)


class IssueState(models.TextChoices):
    DRAFT = "draft", "Draft"
    OPEN = "open", "Open"
    CLOSED = "closed", "Closed"


class Issue(models.Model, AuthorizationMixin):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    owner = models.ForeignKey(
        Account, on_delete=models.CASCADE, related_name="owned_issues"
    )
    author = models.ForeignKey(
        Account,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="authored_issues",
    )
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="issues"
    )

    created_at = models.DateTimeField(auto_now_add=True)

    title = models.CharField(max_length=512)
    content = models.TextField()
    state = models.CharField(max_length=16, default=IssueState.OPEN)

    def notify_everyone_with_access_about_something(self):
        accounts_to_notify = self.get_authorized_accounts(
            self.authorization_scheme.Perms.ISSUE_VIEW
        )

        return send_mail(
            subject="Your attention is needed!!!!!",
            message=f"Hi, this is an urgent notification about issue {self.title} something something.",
            recipient_list=[
                account.email
                for account in accounts_to_notify
                if not account.is_organization
            ],
            from_email="<>",
        )


class HistoricIssueVersion(models.Model):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    issue = models.ForeignKey(Issue, on_delete=models.CASCADE)

    actor = models.ForeignKey(Account, null=True, blank=True, on_delete=models.SET_NULL)

    created_at = models.DateTimeField(auto_now_add=True)

    content = models.TextField()
    state = models.CharField(max_length=16, default=IssueState.OPEN)


class Assignation(models.Model):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    issue = models.ForeignKey(Issue, on_delete=models.CASCADE)
    user = models.ForeignKey(Account, null=True, blank=True, on_delete=models.SET_NULL)


class Comment(models.Model):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    issue = models.ForeignKey(Issue, on_delete=models.CASCADE)

    author = models.ForeignKey(
        Account, null=True, blank=True, on_delete=models.SET_NULL
    )

    created_at = models.DateTimeField(auto_now_add=True)

    content = models.TextField()
