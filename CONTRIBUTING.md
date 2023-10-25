# Contributing to Cedar

Cedar is a community project that is built and maintained by people just like **you**. We're glad you're interested in helping out. There are several different ways you can do it, but before we talk about that, let's talk about how to get started.

## First Things First

1. **When in doubt, open an issue** - For almost any type of contribution, the first step is opening an issue. Even if you think you already know what the solution is, writing down a description of the problem you're trying to solve will help everyone get context when they review your pull request. If it's truly a trivial change (e.g. spelling error), you can skip this step — but as the subject says, when in doubt, [open an issue](https://github.com/cedar-policy/cedar/issues). DO NOT open an issue for security-related issues. See [SECURITY](SECURITY.md).
2. **Only submit your own work**  (or work you have sufficient rights to submit) - Please make sure that any code or documentation you submit is your work or you have the rights to submit. We respect the intellectual property rights of others.

## Ways to Contribute

### Bug Reports

A bug is when software behaves in a way that you didn't expect and the developer didn't intend. To help us understand what's going on, we first want to make sure you're working from the latest version. Please make sure you're testing against the latest version.

Once you've confirmed that the bug still exists in the latest version, you'll want to check to make sure it's not something we already know about on the [open issues GitHub page](https://github.com/cedar-policy/cedar/issues).

If you've upgraded to the latest version and you can't find it in our open issues list, then you'll need to tell us how to reproduce it. To make the behavior as clear as possible, please provide your policies, entities, request, and CLI commands.

The easier it is for us to recreate your problem, the faster it is likely to be fixed. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

### Feature Requests

If you've thought of a way that Cedar could be better, we want to hear about it. We track feature requests using GitHub, so please feel free to open an issue which describes the feature you would like to see, why you need it, and how it should work.

### Documentation Changes

If you would like to contribute to the documentation hosted on docs.cedarpolicy.com, please do so in the [documentation](https://github.com/cedar-policy/cedar-docs) repo.

### Contributing Code

As with other types of contributions, the first step is to [**open an issue on GitHub**](https://github.com/cedar-policy/cedar/issues). Opening an issue before you make changes makes sure that someone else isn't already working on that particular problem. It also lets us all work together to find the right approach before you spend a bunch of time on a PR. So again, when in doubt, open an issue.

If you would like to propose a change to the Cedar language, or suggest a substantial new feature, please [follow the RFC process](https://github.com/cedar-policy/rfcs).

## Changelog

Cedar maintains changelogs for the public-facing crates [cedar-policy](./cedar-policy/CHANGELOG.md) and [cedar-policy-cli](./cedar-policy-cli/CHANGELOG.md), which adhere to the [Keep A Changelog](https://keepachangelog.com/en/1.0.0/) format. The purpose of the changelog is for the contributors and maintainers to incrementally build release notes throughout the development process to avoid the painful and error-prone process of attempting to compile the release notes at release time. On each release the "unreleased" entries of the changelog are moved under the appropriate header. Also, incrementally building the changelog provides a concise, human-readable list of significant features that have been added to the unreleased version under development.

### Which changes require a changelog entry?

Changelogs are intended for developers integrating with libraries and APIs, and end-users interacting with Cedar policies (collectively referred to as "user"). In short, any change that a user of Cedar might want to be aware of should be included in the changelog. The changelog is *not* intended to replace the git commit log that developers of Cedar itself rely upon. The following are some examples of changes that should be in the changelog:

* A newly added feature
* A fix for a user-facing bug
* Dependency updates
* Fixes for security issues

The following are some examples where a changelog entry is not necessary:

* Adding, modifying, or fixing tests
* An incremental PR for a larger feature (such features should include *one* changelog entry for the feature)
* Documentation changes or code refactoring
* Build-related changes

### Where should I put my changelog entry?

For a PR to the `main` branch, add your entry under the "Unreleased" section. For a PR to one of the `release/X.Y.Z` branches, add your entry under the appropriate version header. Once a version is released on crates.io, make sure to update the changelog on `main` to include the new release.

## Review Process

We deeply appreciate everyone who takes the time to make a contribution. We will review all contributions as quickly as possible. As a reminder, [opening an issue](https://github.com/cedar-policy/cedar/issues) discussing your change before you make it is the best way to smooth the PR process. This will prevent a rejection because someone else is already working on the problem, or because the solution is incompatible with the architectural direction.

During the PR process, expect that there will be some back-and-forth. Please try to respond to comments in a timely fashion, and if you don't wish to continue with the PR, let us know. If a PR takes too many iterations for its complexity or size, we may reject it. Additionally, if you stop responding we may close the PR as abandoned. In either case, if you feel this was done in error, please add a comment on the PR.

If we accept the PR, a maintainer will merge your change and usually take care of backporting it to appropriate branches ourselves.

If we reject the PR, we will close the pull request with a comment explaining why. This decision isn't always final: if you feel we have misunderstood your intended change or otherwise think that we should reconsider then please continue the conversation with a comment on the PR and we'll do our best to address any further points you raise.

 Before sending us a pull request, please ensure that:

1. You are working against the latest source on the *main* branch.
2. You check existing open, and recently merged, pull requests to make sure someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work - we would hate for your time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing. If you also reformat all the code, it will be hard for us to focus on your change.
3. Ensure local tests pass.
4. Commit to your fork using clear commit messages.
5. Send us a pull request, answering any default questions in the pull request interface.
6. Pay attention to any automated CI failures reported in the pull request, and stay involved in the conversation.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/) and [creating a pull request](https://help.github.com/articles/creating-a-pull-request/).

## Finding Ways to Contribute

Looking at the existing issues is a great way to find something to contribute on. Looking at any issues labeled as 'help-wanted' or 'good-first-issue' is a great place to start.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct). For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact [opensource-codeofconduct@amazon.com](mailto:opensource-codeofconduct@amazon.com) with any additional questions or comments.

## Security Issues

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue. See [SECURITY](SECURITY.md).

## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.
