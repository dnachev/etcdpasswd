# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

## [1.2.1] - 2021-09-15

## Changed
- upgrade golang to 1.17 (#53)

## [1.2.0] - 2021-05-26

### Changed
- Support etcd 3.4 as a backend store in addtion to etcd 3.3 (#49).
- Flags for `etcdpasswd` command is changed from single dash (`-config`) to double dash (`--config`) (#50).

## [1.1.2] - 2021-05-07

### Changed
- Update etcdutil version to 1.3.6 (#47)

## [1.1.1] - 2021-04-12

### Changed
- Upgrade go version to 1.16 (#38)
- Update release workflow (#39)

## [1.1.0] - 2021-02-01

### Changed
- Update etcdutil to 1.3.5 and other dependencies (#36)
- Test on Ubuntu 20.04 (#36)

## [1.0.0] - 2019-08-19

### Changed
- Update etcdutil to 1.3.2 (#27).

## [0.7] - 2019-01-16

### Changed
- Change location of config files (#16).

### Added
- Opt in to [Go modules](https://github.com/golang/go/wiki/Modules) (#12).

### Changed
- Update etcdutil to v1.3.1 (#14).
- Use cybozu-go/well (#15).

## [0.6] - 2019-01-16

(invalid release due to misoperation)

## [0.5] - 2018-09-03

### Added
- Show etcdpasswd version by option `-version`.
- Rebuild with latest etcdutil v1.0.0.

## [0.4] - 2018-08-06

### Added

- Support for TLS client authentication for etcd using etcdutil(#8).

## [0.3] - 2018-07-25

### Added
- Add this file.
- Build and upload deb package on GitHub Actions.

## [0.2] - 2018-07-20

### Added
- Add integration tests using [placemat][] VMs.

[placemat]: https://github.com/cybozu-go/placemat
[etcdutil]: https://github.com/cybozu-go/etcdutil
[Unreleased]: https://github.com/cybozu-go/etcdpasswd/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/cybozu-go/etcdpasswd/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/cybozu-go/etcdpasswd/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/cybozu-go/etcdpasswd/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/cybozu-go/etcdpasswd/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/cybozu-go/etcdpasswd/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cybozu-go/etcdpasswd/compare/v0.7...v1.0.0
[0.7]: https://github.com/cybozu-go/etcdpasswd/compare/v0.6...v0.7
[0.6]: https://github.com/cybozu-go/etcdpasswd/compare/v0.5...v0.6
[0.5]: https://github.com/cybozu-go/etcdpasswd/compare/v0.4...v0.5
[0.4]: https://github.com/cybozu-go/etcdpasswd/compare/v0.3...v0.4
[0.3]: https://github.com/cybozu-go/etcdpasswd/compare/v0.2...v0.3
[0.2]: https://github.com/cybozu-go/etcdpasswd/compare/v0.1...v0.2
