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

from rest_framework.permissions import BasePermission


class IsAuthorized(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False

        if not hasattr(view, request.method.lower()):
            return view.http_method_not_allowed(request)

        if not hasattr(view, "action"):
            return view.permission_denied(request)

        if getattr(view, "action", None):
            if view.action == "list" or (
                view.action == "metadata"
                and getattr(view, "authorize_options_as_get", True)
                and not view.detail
            ):
                # The queryset should be filtered accordingly for list
                # Metadata (OPTIONS) is handled the same when it's requested on a url where a GET
                # would produce a list action
                return True
            elif view.action == "create":
                return view.is_authorized_for_unsaved_resource()
            else:
                return self.has_object_permission(
                    request,
                    view,
                    obj=view.get_authorization_model_object(skip_authorization=True),
                )

        return True

    def has_object_permission(self, request, view, obj):
        # TODO: see what to do with "obj" parameter
        # return obj == view.get_authorization_model_object() breaks some cases

        if view.action == "create":
            return view.is_authorized_for_unsaved_resource()

        obj = view.get_authorization_model_object()
        return obj is not None
