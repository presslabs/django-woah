# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2024-02-12
### Changes
- Changed the `object_id` field used for GenericForeignKey in AssignedPerm from TextField to CharField(max_length=40) to fix a MySQL indexing error. Technically this is a breaking change, but this project hasn't been announced yet anyway...
- Bump some deps.

## [0.1.0 - REMOVED] - 2024-02-09
- Initial release.
