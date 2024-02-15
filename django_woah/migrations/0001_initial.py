# Generated by Django 4.2.9 on 2024-02-01 10:57

import django.db.models.deletion
import uuid6
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Membership",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid6.uuid7,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                (
                    "is_outside_collaborator",
                    models.BooleanField(
                        default=False,
                        help_text="Outside collaborators might receive different permissions than members, or even no permissions.",
                    ),
                ),
                (
                    "parent",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="django_woah.membership",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="UserGroup",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid6.uuid7,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                ("name", models.CharField(blank=True, max_length=80)),
                (
                    "kind",
                    models.CharField(
                        choices=[("root", "Root"), ("team", "Team"), ("user", "User")],
                        max_length=16,
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="owned_user_groups",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "parent",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="children",
                        to="django_woah.usergroup",
                    ),
                ),
                (
                    "parent_membership",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="django_woah.membership",
                    ),
                ),
                (
                    "related_user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="related_user_groups",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "root",
                    models.ForeignKey(
                        blank=True,
                        limit_choices_to=models.Q(("kind", "root")),
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="root_descendants",
                        to="django_woah.usergroup",
                    ),
                ),
            ],
        ),
        migrations.AddField(
            model_name="membership",
            name="root_user_group",
            field=models.ForeignKey(
                limit_choices_to=models.Q(("kind", "root")),
                on_delete=django.db.models.deletion.CASCADE,
                related_name="root_memberships",
                to="django_woah.usergroup",
            ),
        ),
        migrations.AddField(
            model_name="membership",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="memberships",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="membership",
            name="user_group",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="memberships",
                to="django_woah.usergroup",
            ),
        ),
        migrations.CreateModel(
            name="AssignedPerm",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid6.uuid7,
                        primary_key=True,
                        serialize=False,
                        unique=True,
                    ),
                ),
                ("perm", models.CharField(max_length=128)),
                ("object_id", models.CharField(blank=True, max_length=40, null=True)),
                ("non_model_resource_id", models.TextField(blank=True, null=True)),
                (
                    "content_type",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="owned_assigned_perms",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "user_group",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="group_assigned_perms",
                        to="django_woah.usergroup",
                    ),
                ),
            ],
        ),
        migrations.AddConstraint(
            model_name="usergroup",
            constraint=models.UniqueConstraint(
                fields=("owner", "kind", "related_user"),
                name="unique_usergroup_owner_kind_related_user",
            ),
        ),
        migrations.AddConstraint(
            model_name="usergroup",
            constraint=models.UniqueConstraint(
                fields=("owner", "parent", "kind", "name"),
                name="unique_usergroup_localized_name",
            ),
        ),
        migrations.AddConstraint(
            model_name="membership",
            constraint=models.UniqueConstraint(
                fields=("user", "user_group"), name="unique_user_to_group_membership"
            ),
        ),
        migrations.AddIndex(
            model_name="assignedperm",
            index=models.Index(
                fields=["content_type", "object_id"],
                name="django_woah_content_b1c192_idx",
            ),
        ),
    ]
