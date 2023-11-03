from rest_framework.permissions import BasePermission


class IsAuthorized(BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        if not request.user and request.user.is_authenticated:
            return False

        if not hasattr(view, request.method.lower()):
            return view.http_method_not_allowed(request)

        if not hasattr(view, "action"):
            return view.permission_denied(request)

        if getattr(view, "action", None):
            if view.action == "list":
                return True
            else:
                return self.has_object_permission(
                    request, view, obj=view.get_authorization_model_object()
                )

        return True

    def has_object_permission(self, request, view, obj):
        if view.action == "create":
            return view.is_authorized_for_unsaved_resource()

        return bool(view.get_authorization_model_object())

        # return q_resources_for_user(user=request.user, resource_klass=obj.__class__)
