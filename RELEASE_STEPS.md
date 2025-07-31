## UMF Release Steps

This document contains all the steps required to make a new release of UMF.

As a helper, we use in this guide these 2 variables:
```bash
  $VERSION=1.1.0-rc1  # New full version, including optional rc suffix as an example
  $VER=1.1            # New major+minor only version
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
1. Make sure remotes are up-to-date on your machine (`git remote update`).
1. Make changes for the release.
1. Create a new tag based on the latest commit - it should follow the format:
  `v<major>.<minor>.<patch>` (e.g., `v0.1.0`).
1. Push the tag and branch to the upstream.
1. Create a new GitHub release using the tag created in the previous step.
1. Update dependent/downstream projects to use the new release tag. If any issues arise
   from integration, apply any necessary hot fixes to `v$VER.x`
   branch and go back to step 2 - to create a patch release. This step can also be tested
   using `rc` version, potentially followed by another `rc` tag.

## Make a release locally

Prepare changes for the release:
- Start of appropriate up-to-date branch:
  - Fetch remotes
    - `git remote update`
  - For patch release, do it from a stable branch:
    - `git checkout v$VER.x` (e.g., checkout `v0.1.x` if this is a `v0.1.1` patch)
    - If previously we decided not to create such branch, create it now, based on the appropriate minor or major tag
  - For major/minor release start from the `main` branch
- Add a new entry to the `ChangeLog`, remember to change the day of the week in the release date
  - For major releases mention API and ABI compatibility with the previous releases
- For major and minor releases, update `UMF_VERSION_CURRENT` in `include/umf/base.h` (the API version)
  - For changes in ops structures, update corresponding UMF_*_OPS_VERSION_CURRENT
- For major and minor releases update ABI version in `.map` and `.def` files
  - These files are defined for all public libraries (`libumf` and `proxy_lib`, at the moment)
  - For minor releases acceptable is only adding new functions/symbols!
- Once all changes are done, build locally (and/or verify changes on CI), including:
  - Verify if scanners/linters/checkers passed
  - Verify if version is set properly, especially in `.dll` and `.so` files
- Commit these changes and tag the release:
  - `git commit -a -S -m "$VERSION release"`
  - `git tag -a -s -m "Version $VERSION" v$VERSION`
- Verify if commit and tag are properly signed:
  - `git verify-commit <commit's sha>`
  - `git verify-tag v$VERSION`
- For major/minor release:
  - If stable branch for this release is required, create it:
    - `git checkout -b v$VER.x`
    - For some short-lived versions, creation of this branch may be skipped
- For major/minor release, when release is done, add an extra "dev" tag on the `main` branch:
  - `git tag -a -s -m "Development version $VERSION+1 - dev1" v$VERSION+1-dev1`
    - for example, when `v0.1.0` is released, the dev tag would be `v0.2.0-dev1`
    - if needed, further in time, an extra dev tag can be introduced, e.g. `v0.2.0-dev2`
  - This way, the `main` branch will introduce itself as the next version
  - "dev" tag can and should be added right after we merge changes from stable to main

## Publish changes

As patch releases should be done on the stable branches, pushing tags and branches differ a little.

**Note:**
> Before pushing to "upstream" it's preferred to push changes into your own fork.
> This allows you to verify the branch and tag manually in GitHub interface, and it will
> trigger the CI on your fork.

For patch release:
  - `git push upstream HEAD:v$VER.x v$VERSION` - push branch and tag

For major/minor release:
  - Push main:
    - `git push upstream HEAD:main v$VERSION`
  - And, if stable branch was also created, push it as well:
    - `git checkout v$VER.x`
    - `git push upstream HEAD:v$VER.x`

When final release is done it's best to merge back changes from stable branch to main.
This situation can happen if the stable branch was created before the final release (e.g.
with one of the RC versions). Thanks to that all the changes, including ChangeLog will land
on the main branch. After such merge-back it's advised to add "dev" tag (described above).

## Announce release

To make the release official:
- Go to [GitHub's releases tab](https://github.com/oneapi-src/unified-memory-framework/releases/new):
  - Tag version: `v$VERSION`, release title: UMF $VERSION, description: copy entry from ChangeLog and format it with no tabs and no characters limit in line
- Announce the release in all appropriate channels

## More information

To assure the community that the release is a valid package from UMF maintainers, it's recommended to sign the release
commit and the tag (`-S`/`-s` parameters in commands above). If you require to generate a GPG key follow
[these steps](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key).
After that you'd also have to add this new key to your GitHub account - please do the steps in
[this guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key).
