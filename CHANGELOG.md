# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [3.0.4] - Unreleased

### Added

### Changed

### Fixed
- `SPAM_FLAG` only matches header values starting with `yes`, `true` or `spam`, not words such as `BAYES_00` (#7).

## [3.0.3] - 2026-10-25

### Added
- `AI_*` scores for the AI classifier categories and signals.
- `MIME_LIMIT_EXCEEDED` and `URL_REDIRECTOR_INSECURE` tags.
- `DKIM2_*` scores.
- `DISPOSABLE_BCC` and `FREEMAIL_BCC` scores.

### Changed
- Replaced the `LLM_*` scores with the `AI_*` scores.
- HTTP lookups use the `refreshInterval` property.

### Fixed
- Renamed `DISPOSABLE_REPLYTO` to `DISPOSABLE_REPLY_TO` to match the tag emitted by the server.

## [3.0.2] - 2026-09-21

### Added

### Changed
- Updated DNSBL rules to use the new `bit_and` function.

### Fixed

## [3.0.1] - 2026-09-06

### Added

### Changed
- Updated `DBL_SPAM` score from `6.5` to `4.5`.

### Fixed

## [3.0.0] - 2026-04-13

### Added

### Changed
- Migrated rule format to v0.16+ JMAP object format.

### Fixed

## [2.0.5] - 2025-12-16

### Added
- `PROB_SPAM_*` and `PROB_HAM_*` scores.

### Changed
- Update `SPAM_TRAP` score from `discard` to `15.0`.

### Fixed

## [2.0.4] - 2025-10-05

### Added

### Changed
- Update `STWT_PHISHTANK` url to use https.
- Download geolite2 ipv4 and ipv6 csv files.
- Remove `gmail.com` and other free mail services from trusted domains.

### Fixed
- Update `MW_SURBL_MULTI` compare to match official documentation.

## [2.0.3] - 2025-06-07

### Added
- Tag `BLOCKED_DOMAIN`.

### Changed

### Fixed

## [2.0.2] - 2025-01-19

### Added
- Remote free email provider list from `https://gist.github.com/okutbay/5b4974b70673dfdcc21c517632c1f984`.
- Remote disposable email list from `https://disposable.github.io/disposable-email-domains/domains_mx.txt`.

### Changed
- Removed Nix DNSBL.
- Removed `disposable-domains` list.
- Removed `freemail-providers` list.

### Fixed

## [2.0.1] - 2025-01-06

### Added
- Tag `RCPT_DOMAIN_IN_MESSAGE`.

### Changed
- Removed known DMARC senders list.
- Removed `ALLOWLIST_DMARC` and `BLOCKLIST_DMARC` tags.

### Fixed

## [2.0.0] - 2025-01-02

### Added
- Initial release.

### Changed

### Fixed
