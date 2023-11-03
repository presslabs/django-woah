import json
import numbers
from decimal import Decimal
from collections import OrderedDict

import pytest
from rest_framework.exceptions import ErrorDetail
from rest_framework.test import APIClient

from django_woah.models import (
    create_root_user_group_for_account,
    add_user_to_user_group,
)
from .models import Account


class JSONApiClient(APIClient):
    def generic(self, *args, **kwargs):
        if "format" not in kwargs:
            kwargs["format"] = "json"

        response = super().generic(*args, **kwargs)

        # some response can return empty responses
        if hasattr(response, "data"):
            response.data = self._to_dict(response.data)

        return response

    def _to_dict(self, response):
        if isinstance(response, (str, bytes)):
            try:
                candidate_response = json.loads(response)
                if isinstance(candidate_response, numbers.Number):
                    return response

                return candidate_response

            except ValueError:
                pass

        if isinstance(response, OrderedDict):
            response = dict(response)

        if isinstance(response, (list, set)):
            response = [self._to_dict(item) for item in response]
        elif isinstance(response, dict):
            response = {key: self._to_dict(response[key]) for key in response}
        elif isinstance(response, Decimal):
            response = str(Decimal)
        elif isinstance(response, ErrorDetail):
            response = str(response)

        return response


@pytest.fixture()
def account(db):
    return Account.objects.create(username="account", email="account@accounts.issues")


@pytest.fixture()
def unrelated_account(db):
    return Account.objects.create(
        username="unrelated_account", email="unrelated_account@accounts.issues"
    )


@pytest.fixture()
def organization(account):
    org = Account.objects.create(
        username="organization",
        email="organization@accounts.issues",
        is_organization=True,
    )

    root_org_user_group = create_root_user_group_for_account(org)
    add_user_to_user_group(user=account, user_group=root_org_user_group)

    return org


@pytest.fixture()
def unrelated_organization(unrelated_account):
    org = Account.objects.create(
        username="unrelated_organization",
        email="unrelated_organization@accounts.issues",
        is_organization=True,
    )

    root_org_user_group = create_root_user_group_for_account(org)
    add_user_to_user_group(user=unrelated_account, user_group=root_org_user_group)

    return org


@pytest.fixture()
def api_client(account):
    client = JSONApiClient()
    client.force_authenticate(user=account)
    return client
