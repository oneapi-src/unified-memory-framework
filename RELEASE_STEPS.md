## UMF Release Steps

This document contains all the steps required to make a new release of UMF.

As a helper, we use in this guide these 2 variables:
```bash
  set $VERSION = new full version (e.g., 0.1.0-rc1) # -rc1 included just as an example
  set $VER = new major+minor only version (e.g., 0.1)
```

**Note:**
> Before doing the final release, it's recommended to prepare a pre-release version - a "release candidate"
> (or "rc" in short). This requires adding, e.g., `-rc1` to the VERSION string. When all tests and checks
> end properly, you can follow up with the final release. If any fix is required, it should be included in
> another rc version (e.g., `-rc2`).

At the moment, UMF releases are aligned with oneAPI releases - at least one UMF version
will be released for a oneAPI release. Once all changes planned for UMF release are accepted,
we follow the process (described in more detail below):

1. Checkout the appropriate branch (`main` or "stable" `v$VER.x`).
2. Make changes for the release.
3. Create a new tag based on the latest commit - it takes the form
  `v<major>.<minor>.<patch>` (e.g., `v0.1.0`).
4. Push the tag and branch to the upstream.
5. Create a new GitHub release using the tag created in the previous step.
6. Update downstream projects to utilize the release tag. If any issues arise
   from integration, apply any necessary hot fixes to `v$VER.x`
   branch and go back to step 2 - to create a patch release. This step can also be tested
   using `rc` version, potentially followed by another `rc` tag.

## Make a release locally

Do changes for a release:
- Start of appropriate branch:
  - For patch release, do it from a stable branch:
    - `git checkout v$VER.x` (e.g., checkout `v0.1.x` if this is a `v0.1.1` patch)
    - If previously we decided not to create such branch, create it now, based on the appropriate minor or major tag
  - For major/minor release start from the `main` branch
- Add an entry to ChangeLog, remember to change the day of the week in the release date
  - For major releases mention API and ABI compatibility with the previous release
- Update project's version in a few places:
  - For major and minor releases: `UMF_VERSION_CURRENT` in `include/umf/base.h` (the API version)
  - `release` variable in `scripts/docs_config/conf.py` (for docs)
  - `UMF_VERSION` variable in `.github/workflows/basic.yml` (for installation test)
- For major releases update ABI version in `.map` and `.def` files
  - These files are defined for all public libraries (`libumf` and `proxy_lib`, at the moment)
- Commit these changes and tag the release:
  - `git commit -a -S -m "$VERSION release"`
  - `git tag -a -s -m "Version $VERSION" v$VERSION`
- For major/minor release:
  - If stable branch for this release is required, create it:
    - `git checkout -b v$VER.x`
    - For some early versions (like `0.1.0`) we may omit creation of the branch

## Publish changes

As patch releases should be done on the stable branches, pushing tags and branches differ a little.

For patch release:
  - `git push upstream HEAD:v$VER.x v$VERSION` - push branch and tag

For major/minor release:
  - Push main:
    - `git push upstream HEAD:main v$VERSION`
  - And, if stable branch was also created, push it as well:
    - `git checkout v$VER.x`
    - `git push upstream HEAD:v$VER.x`

## Announce release

To make the release official:
- Go to [GitHub's releases tab](https://github.com/oneapi-src/unified-memory-framework/releases/new):
  - Tag version: `v$VERSION`, release title: UMF $VERSION, description: copy entry from ChangeLog and format it with no tabs and no characters limit in line
  - Prior to version 1.0.0, check the *Set as a pre-release* tick box.
- Announce the release, where needed

## More information

To assure the community that the release is a valid package from UMF maintainers, it's recommended to sign the release
commit and the tag (`-S`/`-s` parameters in commands above). If you require to generate a GPG key follow
[these steps](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key).
After that you'd also have to add this new key to your GitHub account - please do the steps in
[this guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key).
