## Publishing a release
To publish release version to Sonatype, do the following:
- make a tag with version number `vX.Y.Z` (used by `sbt-dynver` to set `version` in `build.sbt`);
- use the new tag to make a Github release, which triggers [`release.yml`](.github/workflows/release.yml) workflow and publishes release version to Sonatype;
