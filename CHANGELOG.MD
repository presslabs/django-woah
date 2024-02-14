# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2024-02-14
### Changes
These are **Breaking Changes**, but the project hasn't been announced yet anyway:
- Renamed `uuid` PKs to simply `id`, and changed the AssignedPerms PK field to UUID7 too.
- Removed `display_name` from UserGroup and shrunk `name` field to 80 chars.


## [0.1.1 - REMOVED] - 2024-02-12
### Changes
- Changed the `object_id` field used for GenericForeignKey in AssignedPerm from TextField to CharField(max_length=40) to fix a MySQL indexing error. This is a **Breaking Change**, but the project hasn't been announced yet anyway.
- Bump some deps.


## [0.1.0 - REMOVED] - 2024-02-09
- Initial release.