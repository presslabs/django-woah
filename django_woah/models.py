import uuid6
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import Q, UniqueConstraint


class AutoCleanModel(models.Model):
    class Meta:
        abstract = True

    def _init_states(self):
        self.initial_state = self.current_state

        self.cleaned_state = {} if not self.pk else self.initial_state.copy()
        self.saved_state = {} if not self.pk else self.initial_state.copy()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._init_states()

    @property
    def current_state(self):
        return {
            field.name: self.__dict__[field.attname]
            for field in self._meta.fields
            if field.attname in self.__dict__
        }

    @staticmethod
    def _states_diff(state, other_state):
        return {key: value for key, value in other_state.items() if value != state[key]}

    def get_dirty_fields(self):
        return self._states_diff(self.current_state, self.cleaned_state)

    def get_unsaved_fields(self):
        if not self.saved_state:
            return list(self.current_state.keys())

        return list(self._states_diff(self.current_state, self.saved_state).keys())

    @property
    def is_cleaned(self):
        if not getattr(self, ".cleaned", False):
            return False

        return not self.get_dirty_fields()

    @is_cleaned.setter
    def is_cleaned(self, value):
        if value:
            self.cleaned_state = self.current_state.copy()

        setattr(self, ".cleaned", value)

    def save(self, *args, **kwargs):
        if not self.is_cleaned:
            self.full_clean()

        super().save(*args, **kwargs)

        self.initial_state = self.current_state.copy()
        if kwargs.get("update_fields") is None:
            self.saved_state = self.current_state.copy()
        else:
            for field in kwargs["update_fields"]:
                if field not in self.current_state:
                    continue

                self.saved_state[field] = self.current_state[field]

    def refresh_from_db(self, *args, **kwargs):
        super().refresh_from_db(*args, **kwargs)

        self._init_states()

    def full_clean(self, *args, **kwargs):
        if self.is_cleaned:
            return

        super().full_clean(*args, **kwargs)

        self.is_cleaned = True


class UserGroupKind(models.TextChoices):
    ROOT = "root", "Root"
    TEAM = "team", "Team"
    USER = "user", "User"


class UserGroup(AutoCleanModel):
    KINDS = UserGroupKind

    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)
    name = models.CharField(max_length=128, null=True, blank=True)
    display_name = models.CharField(max_length=256, null=True, blank=True)
    kind = models.CharField(choices=UserGroupKind.choices, max_length=16)

    owner = related_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="owned_user_groups",
        on_delete=models.CASCADE,
    )

    parent = models.ForeignKey(
        "self", related_name="children", null=True, blank=True, on_delete=models.CASCADE
    )
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

    # rename to parent_user
    # TODO: is this needed anymore, now that there is an owner field that points to org user
    related_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="related_user_groups",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
    )

    def full_clean(self, *args, **kwargs):
        if self.kind == self.KINDS.ROOT:
            try:
                self.related_user
            except UserGroup.related_user.RelatedObjectDoesNotExist:
                self.related_user = self.owner

        return super().full_clean(*args, **kwargs)

    def clean(self):
        if self.root and not self.parent:
            raise ValidationError(
                "A parent must be specified for a non-root UserGroup."
            )

        if self.kind == UserGroupKind.USER and not self.parent_membership:
            raise ValidationError(
                "A parent membership must be specified for a user UserGroup."
            )

        if not self.name:
            username = ""
            if self.kind == UserGroupKind.USER:
                username = f"user:{self.related_user.name} "

            self.name = "".join(
                element
                for element in [self.owner.name, username, str(UserGroup)]
                if element
            )


class AuthorizationManager(models.Manager):
    use_for_related_fields = True

    def get_queryset(self):
        return super().get_queryset().select_related("root")


class Authorization(AutoCleanModel):
    user_group = models.ForeignKey(
        UserGroup, on_delete=models.CASCADE, related_name="authorizations"
    )
    root = models.ForeignKey(
        UserGroup,
        on_delete=models.CASCADE,
        related_name="org_authorizations",
        limit_choices_to=Q(kind=UserGroupKind.ROOT),
    )
    role = models.CharField(max_length=128)

    content_type = models.ForeignKey(ContentType, models.CASCADE, null=True, blank=True)
    object_id = models.TextField(null=True, blank=True)
    resource = GenericForeignKey("content_type", "object_id")

    resource_id = models.TextField(null=True, blank=True)

    restriction = models.TextField(null=True, blank=True)

    objects = AuthorizationManager()

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id"]),
        ]

    def __str__(self):
        target = "*" if not self.object_id else f"{self.content_type, self.object_id}"

        return f"{self.role}, target:{target}, for:{self.user_group}"

    def clean(self):
        resource_data = [self.content_type, self.object_id]
        if any(resource_data) and not all(resource_data):
            raise ValidationError(
                "Both or neither content_type and self.object_id must be specified."
            )

        if self.resource and self.resource_id:
            raise ValidationError(
                "Both a resource and a resource_id may not be specified."
            )

        try:
            self.root
        except Authorization.root.RelatedObjectDoesNotExist:
            self.root = self.user_group.root or self.user_group

        if self.root.kind != UserGroup.KINDS.ROOT:
            raise ValidationError("Root UserGroup must have kind=UserGroup.KINDS.ROOT")


class Membership(AutoCleanModel):
    uuid = models.UUIDField(default=uuid6.uuid7, unique=True, primary_key=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships"
    )

    user_group = models.ForeignKey(
        UserGroup, on_delete=models.CASCADE, related_name="memberships"
    )

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
            UniqueConstraint(
                fields=("user", "user_group"), name="unique_user_to_group_membership"
            ),
        ]

    def clean(self):
        if self.user_group.parent and not self.parent:
            raise ValidationError(
                "A parent membership must be specified for a membership to a non-Root UserGroup."
            )

        if self.user_group.kind == UserGroupKind.USER:
            self.is_outside_collaborator = False

            if not self.user == self.user_group.related_user:
                raise ValidationError(
                    "User must match with the UserGroup(kind=USER) related_user."
                )

        self.root_user_group = self.user_group.root or self.user_group


def create_root_user_group_for_account(account) -> UserGroup:
    return UserGroup.objects.create(
        kind=UserGroupKind.ROOT,
        owner=account,
    )


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

    resulted_membership = Membership.objects.create(
        user=user,
        user_group=user_group,
        root_user_group=root_user_group,
        is_outside_collaborator=is_outside_collaborator,
        parent=parent_membership,
    )

    resulted_user_group = None
    if user_group.kind == UserGroupKind.ROOT:
        resulted_user_group = UserGroup.objects.create(
            kind=UserGroupKind.USER,
            parent=user_group,
            root=user_group,
            owner=user_group.owner,
            related_user=user,
            parent_membership=resulted_membership,
        )

        Membership.objects.create(
            user=user,
            user_group=resulted_user_group,
            root_user_group=root_user_group,
            is_outside_collaborator=False,
            parent=resulted_membership,
        )

    return resulted_membership, resulted_user_group
