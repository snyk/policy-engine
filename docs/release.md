# Release

1.  `changie batch vX.Y.Z` will create `changes/vX.Y.Z.md`.  Inspect that file.
2.  `change merge` to update the `CHANGELOG.md`.
3.  `git add changes/vX.Y.Z.md CHANGELOG.md`
4.  `git commit -m "Bump version to vX.Y.Z"`
5.  `git tag -a -F changes/vX.Y.Z.md v.X.Y.Z`
6.  `git push origin main v.X.Y.Z`
