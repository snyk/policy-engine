# Development

## Releases

Releasing a new version of the policy engine is highly automated.  A new
version can be released by running the following command, from the root of
the repository:

```bash
VERSION=v1.2.3 make release
```

In order to determine the `VERSION`, we use [semantic versioning].

The make target will print out a link to create a PR from a release branch.

Once this PR is merged to `main`, the release is created automatically.

### How this works

 -  We use [changie] to add changes entries on each PR.  These are batched
    together when a version is released and added to CHANGELOG.md.

 -  When we open a new PR, we kick off the
    [rc.yml workflow](../.github/workflows/rc.yml) that tests the release build.

 -  When we merge a `release/*` PR, the
    [release_workflow.yml](../.github/workflows/release_workflow.yml)
    tags the release, and runs [goreleaser] to build the executables and
    upload them to the releases page on GitHub.

There is also a
[release_manual.yml workflow](../.github/workflows/release_manual.yml) that
can be triggered by manually pushing a tag.

[changie]: https://changie.dev/
[semantic versioning]: https://semver.org/
[goreleaser]: https://goreleaser.com/
