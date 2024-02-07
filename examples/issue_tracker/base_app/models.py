import uuid6

from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models


class Account(AbstractBaseUser):
    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

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
    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

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


class Issue(models.Model):
    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

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


class HistoricIssueVersion(models.Model):
    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    issue = models.ForeignKey(Issue, on_delete=models.CASCADE)

    actor = models.ForeignKey(Account, null=True, blank=True, on_delete=models.SET_NULL)

    created_at = models.DateTimeField(auto_now_add=True)

    content = models.TextField()
    state = models.CharField(max_length=16, default=IssueState.OPEN)


class Assignation(models.Model):
    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    issue = models.ForeignKey(Issue, on_delete=models.CASCADE)
    user = models.ForeignKey(Account, null=True, blank=True, on_delete=models.SET_NULL)


class Comment(models.Model):
    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    issue = models.ForeignKey(Issue, on_delete=models.CASCADE)

    author = models.ForeignKey(
        Account, null=True, blank=True, on_delete=models.SET_NULL
    )

    created_at = models.DateTimeField(auto_now_add=True)

    content = models.TextField()
