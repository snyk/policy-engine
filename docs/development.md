# Development

## Releases

Releasing a new version of the policy engine is highly automated.  A new
version can be released by running the following command, from the root of
the repository:

```bash
VERSION=v1.2.3 make release
```

In order to determine the `VERSION`, we use [semantic versioning].

### How this works

 -  We use [changie] to add changes entries on each PR.  These are batched
    together when a version is released and added to CHANGELOG.md.

 -  We push the new tag to GitHub.  There is a [release GitHub action] that
    takes care of the actual release.  This way the release cannot contain
    unstaged local changes etc.

 -  The GitHub action uses [goreleaser] to build the different executables
    and upload them to the releases page on GitHub.

[changie]: https://changie.dev/
[semantic versioning]: https://semver.org/
[release GitHub action]: ../.github/workflows/release.yml
[goreleaser]: https://goreleaser.com/
