# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
N/A

## [0.3.1] - 2025-02-27
### Fixed
- Fix not calling content_type.model_class (because it's a method, not a property like the name would suggest); fixes usage of is_directly_authorized_for_prefetched_resource in some cases
- Add missing CombinedCondition.get_memberships_q; fixes usage of is_authorized_for_prefetched_resources in some cases
- Fix case of infinite recursion in is_authorized_for_prefetched_resources
- Fix calling scheme.is_authorized_for_prefetched_resource directly
- Improve scheme.is_directly_authorized_for_prefetched_resource


## [0.3] - 2025-02-21
### Added
- Added a `get_memberships_q` `Solver/AuthorizationScheme/IndirectPerm/Condition` method, similar to the `get_assigned_perms_q` one. 
  - It is currently required for fetching all authorized actors, but it is not used when fetching the authorized on resources, so it's optionality is to be decided.
- Added an `is_authorized_for_prefetched_resource` method similar to the `is_authorized_for_unsaved_resource`.
  - It is currently used when fetching all authorized actors for a resource + perm combination.
  - The current plan is to later merge this into a single `is_authorized_for_resource` method.
- Added an experimental method (AuthorizationSolver.get_actors_queryset(context)) for querying what users have a certain Perm on a certain resource.
- Added a couple more utils for handling Qs, but as always these are not really meant to be public and may be changed or removed at any time.

### Changed
- Change mentions of "authorized_resources" to "authorized_on_resources". So `get_authorized_resources_q` and `get_authorized_resources_queryset` methods become `get_authorized_on_resources_q` and `get_authorized_on_resources_queryset`. **Breaking Change**
- Improved `assign_perm` helper to optionally receive a `for_resource` parameter.
- Allow `AssignedPerm.objects.create()` to receive a `resource` parameter.

### Fixed
- Preserve explicit and model defined ordering when passing a `base_queryset` to `AuthorizationSolver.get_authorized_on_resources_queryset`
- Handle case of related object being `None` in `HasRelatedResourcePerms.is_authorized_for_unsaved_resource`
- Handle case when trying to `assign_perm` to a user, on an account it doesn't have membership to.
- Fixed `TransitiveFromRelationPerms.is_authorized_for_unsaved_resource`
- Improved `TransitiveFromRelationPerms.get_assigned_perms_q`


## [0.2] - 2024-11-19
### Added
- Add a check for the first field in HasRelatedResourcePerms.relation
- Add uniqueness checks for PermEnum values
- Provide a DRF AuthorizationModelViewSet class for convenience
- Add initial support for simple DRF Views (non-Viewset)
- Added `get_root_membership` `get_single_user_user_group`, and `get_root_user_group` helper funcs.
- Added experimental (as in this might be later removed) operators to Conditions, such that you could write some logic like:
    ```python
    def get_indirect_perms(self, context: Context) -> list[IndirectPerms]:
       return [
           (HasRootMembership(context.actor) | HasSameResourcePerms([self.Roles.OWNER]))
                >> [
                    self.Perms.ACCOUNT_VIEW_MINIMAL,
                ],
        ]
    ```

### Changed
- Lax some in-code assumptions to allow using non-Model classes
- Renamed `ModelAuthorizationScheme`s `direct_authorization_is_allowed` to `allow_directly_assigned_perms`. **Breaking Change**
- Renamed `get_or_create_root_user_group_for_account` helper func to `get_or_create_root_user_group`. **Breaking Change**
- Renamed `get_or_create_team_user_group_for_account` helper func to `get_or_create_team_user_group`. **Breaking Change**

### Fixed
- Fixed a bunch of 500 errors in DRF browsable API mostly related to unsaved resources, but also DRF quirks.
- Handled some attribute traversal errors exceptions, where it was sensible to do so.


## [0.1.3] - 2024-02-15
### Changed
- Add a (semi) uniqueness constraint for UserGroup names. Reusing the initial migration, which is a **Breaking Change**, but as mentioned before, the project is not public yet.


## [0.1.2 - REMOVED] - 2024-02-14
### Changed
These are **Breaking Changes**, but the project hasn't been announced yet anyway:
- Renamed `uuid` PKs to simply `id`, and changed the AssignedPerms PK field to UUID7 too.
- Removed `display_name` from UserGroup and shrunk `name` field to 80 chars.


## [0.1.1 - REMOVED] - 2024-02-12
### Changed
- Changed the `object_id` field used for GenericForeignKey in AssignedPerm from TextField to CharField(max_length=40) to fix a MySQL indexing error. This is a **Breaking Change**, but the project hasn't been announced yet anyway.
- Bump some deps.


## [0.1.0 - REMOVED] - 2024-02-09
- Initial release.
