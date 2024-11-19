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

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from django_woah.models import (
    Membership,
    UserGroup,
    add_user_to_user_group,
    AssignedPerm,
)
from ..authorization import AuthorizationSolver
from ..models import Account, Issue


class AccountSummarySerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="account-detail", lookup_field="id", lookup_url_kwarg="account_id"
    )

    class Meta:
        model = Account

        fields = [
            "username",
            "is_organization",
            "email",
            "name",
            "is_organization",
            "url",
        ]


class IssueSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="issue-detail", lookup_field="id", lookup_url_kwarg="issue_id"
    )
    owner = AccountSummarySerializer()

    class Meta:
        model = Issue

        fields = [
            "url",
            "owner",
            "title",
            "content",
        ]


class UserGroupSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="user-group-detail",
        lookup_field="id",
        lookup_url_kwarg="user_group_id",
    )
    parent = serializers.HyperlinkedRelatedField(
        view_name="user-group-detail",
        lookup_field="id",
        lookup_url_kwarg="user_group_id",
        read_only=True,
    )
    root = serializers.HyperlinkedRelatedField(
        view_name="user-group-detail",
        lookup_field="id",
        lookup_url_kwarg="user_group_id",
        read_only=True,
    )

    class Meta:
        model = UserGroup

        fields = [
            "url",
            "kind",
            "parent",
            "root",
        ]


class MembershipSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="membership-detail",
        lookup_field="id",
        lookup_url_kwarg="membership_id",
    )
    user = serializers.HyperlinkedRelatedField(
        view_name="account-detail",
        lookup_field="id",
        lookup_url_kwarg="account_id",
        queryset=Account.objects.all(),
        write_only=True,
    )
    user_summary = AccountSummarySerializer(source="user", read_only=True)
    user_group = serializers.HyperlinkedRelatedField(
        view_name="user-group-detail",
        lookup_field="id",
        lookup_url_kwarg="user_group_id",
        queryset=UserGroup.objects.all(),
    )

    class Meta:
        model = Membership

        fields = [
            "url",
            "user",
            "user_summary",
            "user_group",
        ]

    def create(self, validated_data):
        return add_user_to_user_group(
            user=validated_data["user"],
            user_group=validated_data["user_group"],
        )[0]


class ResourceHyperlinkedRelatedField(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        self.serializers: list[type[serializers.Serializer]] = kwargs.pop("serializers")

        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        for model_serializer in self.serializers:
            try:
                url_field = model_serializer(context=self.context).fields["url"]

                url_serializer = serializers.HyperlinkedRelatedField(
                    view_name=url_field.view_name,
                    lookup_field=url_field.lookup_field,
                    lookup_url_kwarg=url_field.lookup_url_kwarg,
                    queryset=model_serializer.Meta.model.objects.all(),
                )
                return url_serializer.to_internal_value(data)
            except ValidationError:
                continue

        raise ValidationError(
            serializers.HyperlinkedRelatedField.default_error_messages[
                "incorrect_match"
            ]
        )

    def to_representation(self, value):
        for serializer in self.serializers:
            if value.__class__ == serializer.Meta.model:
                return serializer(context=self.context).to_representation(value)["url"]


class AssignedPermSerializer(serializers.ModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="assigned-perm-detail",
        lookup_field="pk",
        lookup_url_kwarg="privilege_id",
    )
    user_group = serializers.HyperlinkedRelatedField(
        view_name="user-group-detail",
        lookup_field="id",
        lookup_url_kwarg="user_group_id",
        queryset=UserGroup.objects.all(),
    )

    # TODO: Check subclasses of AuthorizationViewSetMixin and register models and views from there
    # In case of duplicates raise Error (unless they have a common URL path? eh this becomes complicated)
    # Would still need to add a way to register resource URL mapping, but maybe that can be done through
    # simple inheritance...
    # resource = serializers.HyperlinkedRelatedField(
    #     view_name="user-group-detail",
    #     lookup_field="id",
    #     lookup_url_kwarg="user_group_id",
    #     queryset=UserGroup.objects.all(),
    # )
    resource = ResourceHyperlinkedRelatedField(
        serializers=[
            MembershipSerializer,
            AccountSummarySerializer,
            UserGroupSerializer,
            IssueSerializer,
        ]
    )

    class Meta:
        model = AssignedPerm

        fields = [
            "url",
            "user_group",
            "perm",
            "resource",
        ]

    # def create(self, validated_data):
    #     validated_data["root"] = (
    #         validated_data["user_group"].root or validated_data["user_group"]
    #     )
    #
    #     return super().create(validated_data)

    def validate(self, attrs):
        attrs["perm"], _ = AuthorizationSolver.clean_perm(attrs["perm"])
        attrs["owner"] = attrs["user_group"].owner

        return attrs
