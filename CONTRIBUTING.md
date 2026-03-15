# Contributing to CrowdSentinel MCP Server

Thank you for your interest in contributing to the CrowdSentinel MCP Server! CrowdSentinel is an AI-powered threat hunting and incident response MCP server featuring 79+ tools, 6,060+ detection rules, and baseline behaviour analysis. All kinds of contributions are welcome.

## Bug reports

If you think you've found a bug in the CrowdSentinel MCP Server, we welcome your report. It's very helpful if you can provide steps to reproduce the bug, as it makes it easier to identify and fix the issue.

## Feature requests

If you find yourself wishing for a feature that doesn't exist in the CrowdSentinel MCP Server, you are probably not alone. Please do not hesitate to open an issue which describes the feature you would like to see, why you need it, and how it should work.

## Pull requests

If you have a fix or a new feature, we welcome your pull requests. You can follow the following steps:

1. Fork your own copy of the repository to your GitHub account by clicking on
   `Fork` button on [CrowdSentinel's GitHub repository](https://github.com/thomasxm/CrowdSentinels-AI-MCP).
2. Clone the forked repository on your local setup.

    ```bash
    git clone https://github.com/$user/CrowdSentinels-AI-MCP
    ```

   Add a remote upstream to track upstream `CrowdSentinels-AI-MCP` repository.

    ```bash
    git remote add upstream https://github.com/thomasxm/CrowdSentinels-AI-MCP
    ```

3. Create a topic branch.

    ```bash
    git checkout -b <branch-name>
    ```

4. Make changes and commit it locally.

    ```bash
    git add <modifiedFile>
    git commit
    ```

Commit messages could help reviewers better understand what the purpose of the submitted PR is. They could help accelerate the code review procedure as well. We encourage contributors to use **EXPLICIT** commit messages rather than ambiguous ones. In general, we advocate the following commit message types:
- Features: commit message starts with `feat`, for example: "feat: add user authentication module"
- Bug Fixes: commit message starts with `fix`, for example: "fix: resolve null pointer exception in user service"
- Documentation: commit message starts with `doc`, for example: "doc: update API documentation for user endpoints"
- Performance: commit message starts with `perf`, for example: "perf: optimise the performance of user service"
- Refactor: commit message starts with `refactor`, for example: "refactor: reorganise user service to improve code readability"
- Test: commit message starts with `test`, for example: "test: add unit test for user service"
- Chore: commit message starts with `chore`, for example: "chore: update dependencies"
- Style: commit message starts with `style`, for example: "style: format the code in user service"
- Revert: commit message starts with `revert`, for example: "revert: revert the changes in user service"
- CI/CD: commit message starts with `ci`, for example: "ci: update GitHub Actions workflow for Python 3.13 support"

5. Push local branch to your forked repository.

    ```bash
    git push
    ```

6. Create a Pull request on GitHub.
   Visit your fork at `https://github.com/$user/CrowdSentinels-AI-MCP` and click
   `Compare & Pull Request` button next to your `<branch-name>`.

## CI pipeline requirements

All pull requests must pass the CI pipeline before being merged. The pipeline includes:

- **Test matrix**: Tests are run across Python 3.10, 3.11, 3.12, and 3.13 to ensure compatibility.
- **SAST (Static Application Security Testing)**: Bandit and Semgrep are used to analyse the codebase for security issues.
  - **HIGH/ERROR** severity findings will block the merge.
  - **MEDIUM** severity findings appear as warnings but do not block the merge.
- **Secret detection**: The pipeline scans for accidentally committed secrets and credentials.

Please ensure your code passes all checks locally before pushing. You can utilise the project's linting and testing tools to verify your changes.

## Keeping branch in sync with upstream

Click `Sync fork` button on your forked repository to keep your forked repository in sync with the upstream repository.

If you have already created a branch and want to keep it in sync with the upstream repository, follow the below steps:

```bash
git checkout <branch-name>
git fetch upstream
git rebase upstream/main
```

## Release

Releases are managed through GitHub Actions. The process is as follows:

1. A maintainer pushes a version tag (e.g., `v0.3.3`) to the `main` branch.
2. The tag push triggers the release workflow in GitHub Actions.
3. The workflow automatically:
   - Builds the package and publishes it to PyPI.
   - Publishes the updated server to the MCP registry.

Contributors do not need to handle the release process directly. If you believe a new release is warranted, please open an issue or discuss it with the maintainers.
