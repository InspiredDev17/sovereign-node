# Local Release Verification

Repository policy does not explicitly authorize hosted CI or GitHub Actions, so
this repository intentionally commits no hosted workflow. Branch protection,
required remote checks, signing and publication remain owner-operated external
gates.

Run the complete locally supported gate from the repository root:

```text
./scripts/verify-release.sh
```

It runs formatting, locked/offline all-target/all-feature tests, doctests,
Clippy with warnings denied, rustdoc with warnings denied, a release build and
`cargo-deny`. It does not install tools, access secrets, publish artifacts,
deploy software or push Git state.

`cargo audit` is a separate attempted gate because it may not be installed or
its advisory database may require network access. Fuzzing is reported separately
as target-added, target-compiled and target-executed evidence. A local green run
does not establish Linux runtime behavior, multi-host operation, production key
custody, branch protection or production qualification.
