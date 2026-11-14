# Changelog

All notable changes to this project are listed here, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `skillgate --version` prints the version.
- Tests for the plain-text, JSON and SARIF reports.

## [0.1.0] - 2026-09-29

First release. It checks an agent skill before you install it: what it can touch, what it says it does, and whether it changed since you approved it.

- An ignore file, so you can silence a finding you have decided is fine.
- Scanning a skill straight from a GitHub address.
- A GitHub Action that runs the check on pull requests.
- Fewer false alarms: several were found by running it on real skills and fixed before the release.
