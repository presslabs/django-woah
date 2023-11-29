from rest_framework import routers

from .views import (
    IssueViewSet,
    AccountViewSet,
    MembershipViewSet,
    UserGroupViewSet,
    AssignedPermViewSet,
)

router = routers.SimpleRouter(trailing_slash=False)

router.register(r"issues", IssueViewSet, basename="issue")
router.register(r"accounts", AccountViewSet, basename="account")
router.register(r"memberships", MembershipViewSet, basename="membership")
router.register(r"user_groups", UserGroupViewSet, basename="user-group")
router.register(r"assigned_perms", AssignedPermViewSet, basename="assigned-perm")

urlpatterns = router.urls
