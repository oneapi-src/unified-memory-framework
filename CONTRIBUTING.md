# Contributing to UMF (Unified Memory Framework)


<!-- TODO: Add [Naming convention](#naming-convention) section -->
- [Opening new issues](#opening-new-issues)
- [Submitting Pull Requests](#submitting-pull-requests)
    - [Building and testing](#building-and-testing)
    - [Code style](#code-style)
    - [When my PR is merged?](#when-my-PR-is-merged)
    - [Extending public API](#extending-public-api)
    - [License](#license)
    - [Adding new dependency](#adding-new-dependency)

Below you'll find instructions on how to contribute to UMF, either with code changes
or issues. All contributions are most welcome!

## Opening new issues

Please log bugs or suggestions as [GitHub issues](https://github.com/oneapi-src/unified-memory-framework/issues).

When reporting a bug remember about the details, at least:
- version of UMF (hash of a commit or a tag),
- OS and kernel,
- compiler.

When opening a new issue you can pick a predefined type of issue. Please follow
the template and fill in all the information. If your query doesn't match any of
the proposed types, just pick a general issue with no template.

## Submitting Pull Requests

We take outside code contributions to UMF through GitHub pull requests.
You must first create your own fork of the project and submit your changes to a branch.
You can then raise a Pull Request targeting `oneapi-src/unified-memory-framework:main`.
Please try to keep commits neat and in order - please squash your commits to
include only relevant ones (no "fixes after review" or similar).

### Building and testing

Building commands can be found in the top-level Readme file - section
["Build"](./README.md#build).

Before committing you should test locally if all tests and checks pass.
When project is built, enter the build directory and execute:

```bash
$ ctest --output-on-failure
```

Any test's failure will produce error log.

To enable additional checks (including `-Werror` / `/WX` compilation flag), switch on CMake flag
`UMF_DEVELOPER_MODE`. To read more about all available CMake options please see
["CMake standard options"](./README.md#cmake-standard-options) section in the top-level Readme.

### Code style

We use `clang-format` to verify and apply code style changes. To see all rules we require,
please take a look at `.clang-format` file in the root directory of this repository.

To enable code style checks and re-formatting, CMake option `UMF_FORMAT_CODE_STYLE` has to
be switched on. You'll then have two additional CMake targets available.

To verify correct coding style of your changes execute (assuming `build` is your build directory):

```bash
$ cmake -B build -DUMF_FORMAT_CODE_STYLE=ON
$ cmake --build build --target clang-format-check
```

We run this check in our Continuous Integration (CI). So, if any issues were found,
the Pull Request will be blocked from merging. To apply proper formatting (meaning,
to fix the issues) execute the second available CMake target - run a command:

```bash
$ cmake --build build --target clang-format-apply

# Remember to review introduced changes
```

**NOTE**: We use specific clang-format version - **15.0** is required. It can be installed,
e.g., with command: `python -m pip install clang-format==15.0.7`.

### When my PR is merged?

Your Pull Request (PR) will be merged if you meet several requirements - the basic are:
- The project builds properly,
- All tests are executed, and no issues have been reported,
- All checks pass (code style, spelling, etc.),
- Additional requirements are fulfilled (e.g., see below, for a new public API function).

While the most of these requirements are verified via automated scripts run in
Continuous Integration (CI) they are also verified with human touch - **the review**!

Code review has to be done by at least two UMF maintainers. The "maintainers team"
is added to each PR by default, but you can also pick specific people to review
your code. It may speed up a little the review process. If any issues are found by
reviewers they should be fixed by the owner of the PR.

Now, when all GitHub Actions jobs are green, all review discussions are resolved, and
you got two approvals from reviewers - you're good to go - your PR will be merged soon!

### Extending public API

When adding a new public function, you have to make sure to update:
- documentation,
- map files with debug symbols (both .def and .map - for Windows and Linux),
- appropriate examples (to show usage),
- tests.

<!--
### Naming convention
TODO: add this section and re-format whole codebase to use such convention
-->

### License

Unified Memory Framework is licensed under the terms in [LICENSE](./LICENSE.TXT) file. By contributing to the project,
you agree to the license and copyright terms therein and release your contribution under these terms.

**NOTE:**
>Each new file added to the repository has to contain the appropriate license header. To see what
>such a header looks like, you can see an existing file, at best, with the same file extension
>(each type of file may have slightly different formatting and/or comment convention).

With your contributions to this repository you also certify the following:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

In case of any doubt, the maintainer may ask you to certify the above in writing, i.e.
via email or by including a `Signed-off-by:` line at the bottom of your commit message.

Please, use your real name (sorry, no pseudonyms or anonymous contributions.), e.g.:

    Signed-off-by: Joe Smith <joe.smith@email.com>

If you set your `user.name` and `user.email` git configs, you can sign your
commit automatically with `git commit -s`.

### Adding new dependency

Adding each new dependency (including new docker image or a package) should be done in
a separate commit. The commit message should be:

```
New dependency: dependency_name

license: SPDX license tag
origin: https://dependency_origin.com
```
