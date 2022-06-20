# Changelog

## 1.0.0 (unreleased)

* Changed: the previously available functions are now in a `v2` module to be explicitly safe about the output. You need to use from `mx3::v2` to keep existing behavior.
* Changed: the `Mx3Hasher` using the `Hasher` trait is now behind the `hasher` feature.
  * It's an implementation that is undefined to the reference specification.
  * I don't think anyone was using it for deterministic output between versions, but to be safe, it's been placed in an optional feature to make it explicit.
* Added: implementations of version 1 and version 3.

## 0.2.0 (2021-05-01)

* Added no_std compatibility

## 0.1.0 (2021-04-30)

* First commit
