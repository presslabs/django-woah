# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Add a check for the first field in HasRelatedResourcePerms.relation
- Add uniqueness checks for PermEnum values
- Provide a DRF AuthorizationModelViewSet class for convenience
- Add initial support for simple DRF Views (non-Viewset)
- Added `get_root_membership` `get_single_user_user_group`, and `get_root_user_group` helper funcs.

### Changed
- Lax some in-code assumptions to allow using non-Model classes
- Renamed `ModelAuthorizationScheme`s `direct_authorization_is_allowed` to `allow_directly_assigned_perms`. **Breaking Change**
- Renamed `get_or_create_root_user_group_for_account` helper func to `get_or_create_root_user_group`. **Breaking Change**
- Renamed `get_or_create_team_user_group_for_account` helper func to `get_or_create_team_user_group`. **Breaking Change**

### Fixed
- Fix case of None-value in the relation traversal in HasRootMembership


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
