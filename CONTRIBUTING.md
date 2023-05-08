# Contributing to Cedar


Cedar is a community project that is built and maintained by people just like **you**. We're glad you're interested in helping out. There are several different ways you can do it, but before we talk about that, let's talk about how to get started.

Thank you for your interest in contributing to our project. Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests to ensure we have all the necessary
information to effectively respond to your bug report or contribution.


## First Things First

1. **When in doubt, open an issue** - For almost any type of contribution, the first step is opening an issue. Even if you think you already know what the solution is, writing down a description of the problem you're trying to solve will help everyone get context when they review your pull request. If it's truly a trivial change (e.g. spelling error), you can skip this step — but as the subject says, when in doubt, [open an issue](https://github.com/cedar-policy/cedar/issues). DO NOT open an issue for security-related issues. See SECURITY.md.
2. **Only submit your own work**  (or work you have sufficient rights to submit) - Please make sure that any code or documentation you submit is your work or you have the rights to submit. We respect the intellectual property rights of others.

## Ways to Contribute



### Bug Reports

A bug is when software behaves in a way that you didn't expect and the developer didn't intend. To help us understand what's going on, we first want to make sure you're working from the latest version. Please make sure you're testing against the latest version.

Once you've confirmed that the bug still exists in the latest version, you'll want to check to make sure it's not something we already know about on the [open issues GitHub page](https://github.com/cedar-policy/cedar/issues).

If you've upgraded to the latest version and you can't find it in our open issues list, then you'll need to tell us how to reproduce it. To make the behavior as clear as possible, please provided your policies, entities, request, and CLI commands. 

Provide as much information as you can. You may think that the problem lies with your query, when actually it depends on how your data is indexed. The easier it is for us to recreate your problem, the faster it is likely to be fixed. Please try to include as much information as you can. Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

### Feature Requests

If you've thought of a way that Cedar could be better, we want to hear about it. We track feature requests using GitHub, so please feel free to open an issue which describes the feature you would like to see, why you need it, and how it should work.


### Documentation Changes

If you would like to contribute to the documentation, please do so in the [documentation](https://github.com/cedar-policy/cedar-docs) repo. 


### Contributing Code

As with other types of contributions, the first step is to [**open an issue on GitHub**](). Opening an issue before you make changes makes sure that someone else isn't already working on that particular problem. It also lets us all work together to find the right approach before you spend a bunch of time on a PR. So again, when in doubt, open an issue.

Additionally, here are a few guidelines to help you decide whether a particular feature should be included in Cedar.

**Is your feature important to most users of Cedar?**

If you believe that a feature is going to fulfill a need for most users of Cedar, then it belongs in Cedar. However, we don't want every feature built into the core server. If the feature requires additional permissions or brings in extra dependencies it should instead be included as a module in core.

**Is your feature a common dependency across multiple plugins?**

Does this feature contain functionality that cuts across multiple plugins? If so, this most likely belongs in Cedar as a core module or plugin.


## Changelog

Cedar maintains version specific changelog by enforcing a change to the ongoing [CHANGELOG](CHANGELOG.md) file adhering to the [Keep A Changelog](https://keepachangelog.com/en/1.0.0/) format. The purpose of the changelog is for the contributors and maintainers to incrementally build the release notes throughout the development process to avoid a painful and error-prone process of attempting to compile the release notes at release time. On each release the "unreleased" entries of the changelog are moved to the appropriate release notes document in the `./release-notes` folder. Also, incrementally building the changelog provides a concise, human-readable list of significant features that have been added to the unreleased version under development.


### Which changes require a CHANGELOG entry?

Changelogs are intended for operators/administrators, developers integrating with libraries and APIs, and end-users interacting with Cedar Dashboards and/or the REST API (collectively referred to as "user"). In short, any change that a user of Cedar might want to be aware of should be included in the changelog. The changelog is *not* intended to replace the git commit log that developers of Cedar itself rely upon. The following are some examples of changes that should be in the changelog:


* A newly added feature
* A fix for a user-facing bug
* Dependency updates
* Fixes for security issues

The following are some examples where a changelog entry is not necessary:


* Adding, modifying, or fixing tests
* An incremental PR for a larger feature (such features should include *one* changelog entry for the feature)
* Documentation changes or code refactoring
* Build-related changes

Any PR that does not include a changelog entry will result in a failure of the validation workflow in GitHub. If the contributor and maintainers agree that no changelog entry is required, then the `skip-changelog` label can be applied to the PR which will result in the workflow passing.


### How to add my changes to [CHANGELOG](CHANGELOG.md)?

Adding in the change is two step process:

1. Add your changes to the corresponding section within the CHANGELOG file with dummy pull request information, publish the PR
2. Update the entry for your change in [`CHANGELOG.md`](CHANGELOG.md) and make sure that you reference the pull request there.

### Where should I put my CHANGELOG entry?

The changelog on the `main` branch will contain sections for the *next major* and *next minor* releases. Your entry should go into the section it is intended to be released in. In practice, most changes to `main` will be backported to the next minor release so most entries will likely be in that section.

The following examples assume the *next major* release on main is 3.0, then *next minor* release is 2.5, and the *current* release is 2.4.


* **Add a new feature to release in next minor:** Add a changelog entry to `[Unreleased 2.x]` on main, then backport to 2.x (including the changelog entry).
* **Introduce a breaking API change to release in next major:** Add a changelog entry to `[Unreleased 3.0]` on main, do not backport.
* **Upgrade a dependency to fix a CVE:** Add a changelog entry to `[Unreleased 2.x]` on main, then backport to 2.x (including the changelog entry), then backport to 2.4 and ensure the changelog entry is added to `[Unreleased 2.4.1]`.

## Review Process

We deeply appreciate everyone who takes the time to make a contribution. We will review all contributions as quickly as possible. As a reminder, [opening an issue]() discussing your change before you make it is the best way to smooth the PR process. This will prevent a rejection because someone else is already working on the problem, or because the solution is incompatible with the architectural direction.

During the PR process, expect that there will be some back-and-forth. Please try to respond to comments in a timely fashion, and if you don't wish to continue with the PR, let us know. If a PR takes too many iterations for its complexity or size, we may reject it. Additionally, if you stop responding we may close the PR as abandoned. In either case, if you feel this was done in error, please add a comment on the PR.

If we accept the PR, a [maintainer](MAINTAINERS.md) will merge your change and usually take care of backporting it to appropriate branches ourselves.

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

## Finding contributions to work on

Looking at the existing issues is a great way to find something to contribute on. As our projects, by default, use the default GitHub issue labels (enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any 'help wanted' issues is a great place to start.

Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct). For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq) or contact [opensource-codeofconduct@amazon.com](mailto:opensource-codeofconduct@amazon.com) with any additional questions or comments.

## Security issue notifications

If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.

## Licensing

See the [LICENSE](https://vscode-remote+ssh-002dremote-002bclouddesk.vscode-resource.vscode-cdn.net/home/anwmamat/git/cedar/cedar/LICENSE) file for our project's licensing. We will ask you to confirm the licensing of your contribution.
