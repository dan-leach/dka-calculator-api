# Changelog

All notable changes to the BSPED Paediatric DKA Calculator API codebase will be documented in this file.

See also:

- [Client changelog](https://github.com/dan-leach/dka-calculator/blob/main/changelog.md)
- [Contributors](https://github.com/dan-leach/dka-calculator/blob/main/contributors.md) to the project.

## [v1.1] - 2025-02-27 13:45

### Added

- Error handling module including notifications to admin email
- Encryption of audit data stored in database

## [v1.0] - 2025-02-19 11:30

Initial version of the API as a separate Express.js application.

Previous versions of the DKA Calculator performed calculations in the browser and passed audit data to via a PHP API which was part of the client repository.
