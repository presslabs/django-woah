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
from typing import Optional

import uuid6

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db import models, transaction
from django.db.models import Q, UniqueConstraint

from django_woah.utils.models import AutoCleanModel


class UserGroupKind(models.TextChoices):
    ROOT = "root", "Root"
    TEAM = "team", "Team"
    USER = "user", "User"


class UserGroup(AutoCleanModel):
    KINDS = UserGroupKind

    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    name = models.CharField(max_length=80, blank=True)
    kind = models.CharField(choices=UserGroupKind.choices, max_length=16)

    # TODO: should this be nullable?
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="owned_user_groups",
        on_delete=models.CASCADE,
    )

    parent = models.ForeignKey(
        "self", related_name="children", null=True, blank=True, on_delete=models.CASCADE
    )
    # This is some yet to be decided denormalization
    root = models.ForeignKey(
        "self",
        related_name="root_descendants",
        limit_choices_to=Q(kind=UserGroupKind.ROOT),
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    parent_membership = models.OneToOneField(
        "django_woah.Membership", null=True, blank=True, on_delete=models.CASCADE
    )

    # This is some denormalization, but it's possibly useful
    related_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="related_user_groups",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    class Meta:
        constraints = [
            UniqueConstraint(
                fields=("owner", "kind", "related_user"),
                name="unique_usergroup_owner_kind_related_user",
            ),
            UniqueConstraint(
                fields=("owner", "parent", "kind", "name"),
                name="unique_usergroup_localized_name",
            ),
        ]

    def clean(self):
        if self.root and not self.parent:
            raise ValidationError("A parent must be specified for a non-root UserGroup.")

        if self.kind == UserGroupKind.USER and not self.parent_membership:
            raise ValidationError("A parent membership must be specified for a user UserGroup.")

        if not self.name:
            username = ""
            if self.kind == UserGroupKind.USER:
                username = f"user:{str(self.related_user)} "

            self.name = " ".join(
                element for element in [str(self.owner), username, self.kind] if element
            )

    def __str__(self):
        name = f"{self.name}"

        return name


class AssignedPermManager(models.Manager):
    use_for_related_fields = True

    def get_queryset(self):
        return super().get_queryset().select_related("owner")

    def filter(self, *args, **kwargs):
        if kwargs and (resource := kwargs.pop("resource", None)):
            kwargs["content_type"] = ContentType.objects.get_for_model(resource.__class__)
            kwargs["object_id"] = resource.pk

        return super().filter(*args, **kwargs)

    def get(self, *args, **kwargs):
        if kwargs and (resource := kwargs.pop("resource", None)):
            kwargs["content_type"] = ContentType.objects.get_for_model(resource.__class__)
            kwargs["object_id"] = resource.pk

        return super().get(*args, **kwargs)

    def create(self, defaults=None, **kwargs):
        if resource := kwargs.pop("resource", None):
            kwargs["content_type"] = ContentType.objects.get_for_model(resource.__class__)
            kwargs["object_id"] = resource.pk

        return super().create(**kwargs)

    def get_or_create(self, defaults=None, **kwargs):
        if defaults and (resource := defaults.pop("resource", None)):
            defaults["content_type"] = ContentType.objects.get_for_model(resource.__class__)
            defaults["object_id"] = resource.pk

        if resource := kwargs.pop("resource", None):
            kwargs["content_type"] = ContentType.objects.get_for_model(resource.__class__)
            kwargs["object_id"] = resource.pk

        return super().get_or_create(defaults=defaults, **kwargs)


# class AssignedPermAppliesTo(models.TextChoices):
#     ALL = "all", "All"
#     MEMBERS = "members", "Members"
#     OUTSIDE_COLLABORATORS = "outside_collaborators", "Outside Collaborators"


class AssignedPerm(AutoCleanModel):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    user_group = models.ForeignKey(
        UserGroup, on_delete=models.CASCADE, related_name="group_assigned_perms"
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="owned_assigned_perms",
        on_delete=models.CASCADE,
    )
    perm = models.CharField(max_length=128)

    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True, blank=True)
    object_id = models.CharField(null=True, blank=True, max_length=40)
    resource = GenericForeignKey("content_type", "object_id")

    non_model_resource_id = models.TextField(null=True, blank=True)

    # restriction = models.TextField(null=True, blank=True)

    objects = AssignedPermManager()

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id"]),
        ]

    def __str__(self):
        target = "*" if not self.object_id else f"{self.content_type, self.object_id}"

        return f"<{self.perm}>, resource:<{target}>, user_group:<{self.user_group}>"

    def full_clean(self, *args, **kwargs):
        resource_data = [self.content_type, self.object_id]
        if any(resource_data) and not all(resource_data):
            raise ValidationError(
                "Both or neither content_type and self.object_id must be specified."
            )

        if self.resource and self.non_model_resource_id:
            raise ValidationError(
                "Both a resource and a non_model_resource_id may not be specified."
            )

        if (
            not self.resource
            and not self.non_model_resource_id
            and not settings.WOAH_DANGEROUS_ALLOW_UNSPECIFIED_RESOURCE_PERMS
        ):
            print(
                "For model-wide AssignedPerms (object_id=None), consider assigning the perm to the"
                "resource's owner model instead, and use IndirectPerms to indirectly give the perm on the"
                "matching resources.\n"
                "This limitation is in place to prevent an authorization bypass exploit. It will be removed when a "
                "proper fix will be published in a future release.\n"
                "!!! Do not mess with the `WOAH_DANGEROUS_ALLOW_UNSPECIFIED_RESOURCE_PERMS` setting, it only "
                "temporarily exists to facilitate easier testing !!!"
            )
            raise ValidationError(
                "Either a resource or a non model resource id must be specified."
            )

        try:
            self.owner
        except AssignedPerm.owner.RelatedObjectDoesNotExist:
            if not self.resource:
                self.owner = self.user_group.owner

        return super().full_clean(*args, **kwargs)


class Membership(AutoCleanModel):
    id = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships"
    )

    user_group = models.ForeignKey(UserGroup, on_delete=models.CASCADE, related_name="memberships")

    # This is some yet to be decided denormalization
    root_user_group = models.ForeignKey(
        UserGroup,
        on_delete=models.CASCADE,
        related_name="root_memberships",
        limit_choices_to=Q(kind=UserGroupKind.ROOT),
    )

    is_outside_collaborator = models.BooleanField(
        default=False,
        help_text="Outside collaborators might receive different permissions than members, or even no permissions.",
    )

    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.CASCADE)

    class Meta:
        constraints = [
            UniqueConstraint(fields=("user", "user_group"), name="unique_user_to_group_membership"),
        ]

    def clean(self):
        if self.user_group.parent and not self.parent:
            raise ValidationError(
                "A parent membership must be specified for a membership to a non-Root UserGroup."
            )

        if self.user_group.kind == UserGroupKind.USER:
            self.is_outside_collaborator = False

            if not self.user == self.user_group.related_user:
                raise ValidationError("User must match with the UserGroup(kind=USER) related_user.")

        root_user_group = self.user_group.root or self.user_group
        if not root_user_group:
            raise ValidationError("A root_user_group must be specified.")

        self.root_user_group = root_user_group

    def __str__(self):
        return f"user:<{self.user}>, user_group:<{self.user_group}>, is_outside_collaborator:<{self.is_outside_collaborator}>"


def get_root_user_group(owner) -> UserGroup:
    return UserGroup.objects.get(
        kind=UserGroupKind.ROOT,
        owner=owner,
        related_user=owner,
    )


def get_single_user_user_group(related_to_user, owned_by_account) -> UserGroup:
    return related_to_user.related_user_groups.get(owner=owned_by_account)


def get_or_create_root_user_group(owner) -> UserGroup:
    return UserGroup.objects.get_or_create(
        kind=UserGroupKind.ROOT,
        owner=owner,
        related_user=owner,
    )[0]


def get_or_create_team_user_group(owner, name: str) -> UserGroup:
    root = get_root_user_group(owner)

    return UserGroup.objects.get_or_create(
        name=name,
        kind=UserGroupKind.TEAM,
        owner=owner,
        root=root,
        parent=root,
    )[0]


def get_root_membership(user, account) -> Optional[Membership]:
    try:
        return Membership.objects.get(
            user=user,
            user_group__owner=account,
            user_group__kind=UserGroupKind.ROOT,
        )
    except Membership.DoesNotExist:
        return None


@transaction.atomic
def add_user_to_user_group(
    user, user_group: UserGroup, is_outside_collaborator=False
) -> tuple[Membership, UserGroup]:
    if not user_group.root and user_group.kind != UserGroupKind.ROOT:
        raise ValueError("Received a non-Root UserGroup with missing `root` field")

    parent_membership = None
    if user_group.parent:
        parent_membership = user_group.parent.memberships.get(user=user)

    root_user_group = user_group.root or user_group

    resulted_membership = Membership.objects.update_or_create(
        user=user,
        user_group=user_group,
        root_user_group=root_user_group,
        parent=parent_membership,
        defaults={"is_outside_collaborator": is_outside_collaborator},
    )[0]

    resulted_user_group = None
    if user_group.kind == UserGroupKind.ROOT:
        resulted_user_group = UserGroup.objects.update_or_create(
            kind=UserGroupKind.USER,
            parent=user_group,
            root=user_group,
            owner=user_group.owner,
            related_user=user,
            parent_membership=resulted_membership,
        )[0]

        Membership.objects.update_or_create(
            user=user,
            user_group=resulted_user_group,
            root_user_group=root_user_group,
            is_outside_collaborator=False,
            parent=resulted_membership,
        )

    return resulted_membership, resulted_user_group


def create_user_membership_to_account(
    user, account, is_outside_collaborator=False
) -> tuple[Membership, UserGroup]:
    user_group = get_root_user_group(account)

    return add_user_to_user_group(user, user_group, is_outside_collaborator)


def assign_perm(perm, to_user, on_account, for_resource=None) -> AssignedPerm:
    try:
        user_group = get_single_user_user_group(
            related_to_user=to_user, owned_by_account=on_account
        )
    except ObjectDoesNotExist:
        error_message = f"User {to_user} does not have a membership on {on_account}."
        solution = f"To grant the user membership, you may call `create_user_membership_to_account({to_user}, {on_account})`."

        print(f"{error_message}\n{solution}")
        raise ValueError(error_message)

    kwargs = {
        "user_group": user_group,
        "perm": perm,
        "owner": on_account,
    }
    if for_resource:
        kwargs["resource"] = for_resource

    return AssignedPerm.objects.create(**kwargs)
