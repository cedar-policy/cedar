# Cedar security self-assessment

<!-- Structure follows the self-assessment template of the OpenSSF Security Assessments project,
     https://github.com/ossf/security-assessments/blob/main/guidance/self-assessment/template/self-assessment.md (Apache-2.0). -->

This is the Cedar team's security self-assessment of the [cedar-policy/cedar](https://github.com/cedar-policy/cedar) repository.

Last reviewed: 2026-10-26

## Self-assessment outline

### Table of contents

* [Metadata](#metadata)
  * [Security links](#security-links)
* [Overview](#overview)
  * [Background](#background)
  * [Actors](#actors)
  * [Actions](#actions)
  * [Goals](#goals)
  * [Non-goals](#non-goals)
* [Self-assessment use](#self-assessment-use)
* [Attack surface](#attack-surface)
* [Security functions and features](#security-functions-and-features)
* [Project compliance](#project-compliance)
* [Secure development practices](#secure-development-practices)
* [Security issue resolution](#security-issue-resolution)
* [Appendix](#appendix)

### Metadata

|||
| -- | -- |
| Assessment Stage | Complete |
| Software | <https://github.com/cedar-policy/cedar> |
| Security Provider | Yes. Applications use Cedar for access control. |
| Languages | Rust. The formal model in [cedar-spec](https://github.com/cedar-policy/cedar-spec) is written in Lean. The npm package ships TypeScript type definitions. |
| SBOM | No SBOM is published. [Cargo.lock](Cargo.lock) lists every resolved dependency. |

#### Security links

| Doc | URL |
| -- | -- |
| Security policy | [SECURITY.md](SECURITY.md) |
| Security Insights | [security-insights.yml](security-insights.yml) |
| Security of Cedar, and best practices for applications | <https://docs.cedarpolicy.com/other/security.html> |
| Policy validation and its guarantees | <https://docs.cedarpolicy.com/policies/validation.html> |
| Published security advisories | <https://github.com/cedar-policy/cedar/security/advisories> |
| Formal model, proofs, and differential testing | <https://github.com/cedar-policy/cedar-spec> |
| Integration test corpus | <https://github.com/cedar-policy/cedar-integration-tests> |
| Third-party threat model (Trail of Bits, 2024) | <https://github.com/trailofbits/publications/blob/master/reports/Policy_Language_Security_Comparison_and_TM.pdf> |
| OpenSSF Scorecard | <https://scorecard.dev/viewer/?uri=github.com/cedar-policy/cedar> |
| OpenSSF Best Practices | <https://www.bestpractices.dev/projects/11398> |

### Overview

Cedar is a language for writing authorization policies and making authorization decisions based on those policies. An application asks Cedar whether a principal may perform an action on a resource, and Cedar answers Allow or Deny according to the application's policies, or reports an error.

#### Background

Cedar is an authorization policy language designed to be ergonomic, fast, safe, and analyzable.
Rather than embed authorization logic in an application's code, developers can write that logic as Cedar policies and delegate access decisions to Cedar's evaluation engine.
Cedar's simple and intuitive syntax supports common authorization use cases with readable policies, naturally leveraging concepts from role-based, attribute-based, and relation-based access control models.
Cedar's policy structure enables access requests to be decided quickly.
Cedar's policy validator leverages optional typing to help policy writers avoid mistakes, but not get in their way.
Cedar's design has been finely balanced to allow for a sound and complete logical encoding, which enables precise policy analysis, e.g., to ensure that when refactoring a set of policies, the authorized permissions do not change.
Cedar is implemented in Rust and modeled in the Lean programming language, where important formal properties of its design are proven to hold.
Details about the Cedar language can be found in the [OOPSLA paper](https://doi.org/10.1145/3649835).

Cedar was built with verification-guided development (VGD).
A formal model in Lean defines Cedar's semantics, and Lean proofs establish properties of that model.
The Rust implementation in this repository is then tested against the model with differential random testing (DRT).
The approach is described in the Amazon Science post [How we built Cedar with automated reasoning and differential testing](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing) and the paper [How We Built Cedar: A Verification-Guided Approach](https://arxiv.org/abs/2407.01688).

Security is shared between Cedar and the applications that use it, as the [Cedar security documentation](https://docs.cedarpolicy.com/other/security.html#security-shared-responsibility) describes. Cedar is responsible for evaluating policies correctly. The application is responsible for writing policies that express its intent and for giving Cedar accurate data.

This repository contains these crates:

| Crate | Purpose | Published |
| -- | -- | -- |
| [cedar-policy](cedar-policy) | Public Rust library API, and the JSON interface used by the Wasm package | crates.io |
| [cedar-policy-core](cedar-policy-core) | Parser, evaluator, authorizer, validator, and extension functions | crates.io |
| [cedar-policy-formatter](cedar-policy-formatter) | Policy formatter | crates.io |
| [cedar-policy-cli](cedar-policy-cli) | The `cedar` command-line tool | crates.io, GitHub releases |
| [cedar-policy-symcc](cedar-policy-symcc) | Symbolic compiler (SymCC), which turns questions about policies into SMT queries | crates.io |
| [cedar-wasm](cedar-wasm) | WebAssembly build of the JSON interface | npm, as `@cedar-policy/cedar-wasm` |
| [cedar-language-server](cedar-language-server) | Language server for editors | Not published |
| [cedar-testing](cedar-testing) | Test harness | Not published |

#### Actors

| Actor | Role | Trust and isolation |
| -- | -- | -- |
| User | Writes policy and schema, links the Cedar library, builds requests and entity data, calls the authorizer, and enforces the decision | The user is responsible for ensuring the policy, schema, entity store, and request express what's intended. Cedar runs inside the application's process and is not isolated from it. |
| Cedar core | Parses, validates, and evaluates policies, schemas, entities, and requests, and computes authorization decisions ([cedar-policy-core](cedar-policy-core)) | Cedar core trusts none of its inputs, and must behave correctly for any policy, schema, entity, or request. It works entirely in memory: no input can make it reach the host's files, network, or clock, and the evaluation of one policy cannot affect the evaluation of another. |
| Cedar library | The public Rust API over Cedar core, and the policy formatter ([cedar-policy](cedar-policy), [cedar-policy-formatter](cedar-policy-formatter)) | It is built on Cedar core's internal API, and forwards untrusted user input to it. Like Cedar core, it works entirely in memory. |
| JSON interface and Wasm package | JSON-in, JSON-out functions over the Cedar library ([cedar-policy/src/ffi](cedar-policy/src/ffi)), compiled to WebAssembly for JavaScript ([cedar-wasm](cedar-wasm)) | The interface treats every JSON argument as untrusted input. In the Wasm package it runs inside the host's JavaScript runtime and, like Cedar core, works entirely in memory. |
| CLI | The `cedar` binary, with subcommands such as `authorize`, `validate`, `format`, and `symcc` ([cedar-policy-cli](cedar-policy-cli)) | The CLI trusts the user who runs it, and treats the content of the files and standard input it reads as untrusted Cedar input. It runs as an ordinary process with that user's permissions, and only `format`, `link`, and `new` write files. |
| Language server | Editor support over the Language Server Protocol ([cedar-language-server](cedar-language-server)) | The server trusts the editor that starts it, including its choice of schema file, and treats document contents as untrusted Cedar input. It runs as a separate process with the editor user's permissions, and talks to the editor over standard input and output. |
| SymCC and SMT solver | SymCC encodes questions about policies as SMT queries, and cvc5 answers them ([cedar-policy-symcc](cedar-policy-symcc)) | SymCC trusts the cvc5 binary it starts, which comes from the CLI's `--cvc5-path` option, the `CVC5` environment variable, or `PATH`. cvc5 runs as a separate child process that SymCC talks to over pipes, with a 60-second time limit. |
| Release pipeline | GitHub Actions workflows that publish to crates.io, npm, and GitHub releases | Users of the published packages trust the pipeline to publish exactly what is on the release tag. The crates.io and npm publishing jobs run on GitHub-hosted runners, in a `release` environment that only protected branches can use and that needs approval from the `core-cedar-devs` team. |

#### Actions

| Action | Steps |
| -- | -- |
| Authorize | The user passes policies, entity data, and a request to one of the Cedar front-end modules. The data are forwarded to the Cedar core module, which compiles the policies, written in Cedar or JSON syntax, and rejects malformed input. Cedar core then interprets the policies in memory and returns Allow or Deny with the determining policies and any errors. |
| Validate | The user passes policies and a schema to the Cedar library. Cedar core type-checks each policy against the schema and returns errors and warnings, if applicable. |
| Analyze with SymCC | The user passes policies and a schema to SymCC, which first type-checks each policy against the schema. SymCC then encodes the policies as SMT queries, and sends them to cvc5 over pipes. The policies and schema leave the Cedar process only as SMT queries to the local cvc5 child process. |
| Type-aware partial evaluation (TPE) | With the experimental `tpe` feature, the user passes policies, a schema, and a request and entity data with unknown values. Cedar core checks the partial request and entity data against the schema, then evaluates what it can in memory. It returns either a decision or residual policies for future authorization. |

#### Goals

* **Correctness of Cedar's core functionalities.** Authorization, validation, symbolic analysis with SymCC, and type-aware partial evaluation behave as Cedar's Lean model specifies. This holds for any input, including policies, schemas, entities, and requests written by an attacker. The [Cedar paper](https://arxiv.org/abs/2403.04651) lists some notable properties proved about the model: a satisfied `forbid` policy always denies the request, a request with no satisfied `permit` policy is denied, and validated policies evaluate without type errors.
A complete account of Cedar's formal semantics and proven properties can be found in the [cedar-spec GitHub repository](https://github.com/cedar-policy/cedar-spec).

#### Non-goals

* **Faithfulness of policy to user intention.** Do the application's policies, schemas, and entity data express the access control it intends?
* **Policy enforcement.** Cedar returns a decision. The application must enforce it.
* **Input size limits.** Cedar places no limit on the size of policies, schemas, or requests. Services that accept arbitrary input must bound its size to protect against memory exhaustion, as the [security documentation](https://docs.cedarpolicy.com/other/security.html#security-input-validation) says.
* **Storage and distribution of policies.** Where policies and entity data are stored, and who may change them, is up to the application.
* **Isolation from the host process.** Cedar is a library. It does not protect against other code running in the same process.
* **Stack overflow protection on Wasm and Android.** On platforms that the `stacker` crate does not support, Cedar assumes there is enough stack, so very deeply nested input can crash the process.
* **Other implementations.** [cedar-go](https://github.com/cedar-policy/cedar-go) and [cedar-java](https://github.com/cedar-policy/cedar-java) are separate repositories and are not assessed here.
* **Side channels.** Side channels such as timing and power usage are not part of the Cedar model.

### Self-assessment use

This self-assessment is created by the Cedar team to perform an internal analysis of the project's security. It is not intended to provide a security audit of Cedar, or function as an independent assessment or attestation of Cedar's security health.

This document serves to provide Cedar users with an initial understanding of Cedar's security, where to find existing security documentation, Cedar's plans for security, and a general overview of Cedar's security practices, both for the development of Cedar and for the security of Cedar.

This document provides readers with an initial understanding of Cedar to assist in a joint-assessment, necessary for projects under incubation. Taken together, this document and the joint-assessment serve as a cornerstone for if and when Cedar seeks graduation and is preparing for a security audit.

### Attack surface

| Threat | Attack | Impact | Mitigations |
| -- | -- | -- | -- |
| Incorrect authorization behavior | Crafted policies, entities, or requests make the implementation compute a decision the semantics do not specify | A wrong Allow or Deny | Lean proofs of the properties of the design. Differential testing of all features against the Lean model. The integration test corpus. |
| System integrity and confidentiality | A crafted policy, schema, entity, or request tries to make Cedar read files, the network, or the clock | Data tampering/leak from the host | Cedar runs in memory. |
| Memory safety | Input that triggers undefined behavior | Arbitrary code execution in the host | `unsafe` Rust code is forbidden in every crate. Dependencies are checked by cargo-audit and cargo-deny. |
| Memory exhaustion | Input crafted to make parsing, validation, or evaluation use excessive memory or CPU | Denial of service against the host application | Evaluation of bounded input terminates. As it is still possible to exhaust memory, applications need to bound input size. |
| Stack overflow | Deeply nested expressions | A possible crash on Wasm and Android | The evaluator's stack check, and documentation of the platform limitation |
| Panic | Malformed input reaches code that panics | The host process crashes | Clippy denies panicking constructs. Thorough fuzzing. |
| Supply chain attack | A malicious or vulnerable crate enters the build | Any of the above | [Cargo.lock](Cargo.lock), cargo-audit on every pull request, cargo-deny, and Dependabot alerts and updates |
| Compromised release | A tampered package, or a stolen publishing credential | Users install malicious code | crates.io trusted publishing. Publishing jobs run in a `release` environment that needs approval from the core team. npm packages carry build provenance. Gap: CLI binaries on GitHub releases are not signed. |
| CI workflow abuse | Content from an untrusted pull request reaches a workflow with write permissions | Repository or release tampering | `comment_pr.yml` runs code from the default branch and treats the pull request's coverage artifact as data. |

Cedar provides features that encourage good authorization practices. The [security best practices](https://docs.cedarpolicy.com/other/security.html#security-best-practices) detail the principles to follow when using Cedar.

### Security functions and features

**Critical.** These are Cedar's language design and implementation choices. None of them can be configured, and Cedar is secure only if each one is correct. Changes to them are tracked against the formal model: the pull request template asks every contributor whether a change affects the Lean model or differential testing in [cedar-spec](https://github.com/cedar-policy/cedar-spec).

| Component | Location |
| -- | -- |
| Parsers | [parser](cedar-policy-core/src/parser) (Cedar syntax), [est](cedar-policy-core/src/est) (JSON policies), [entities/json](cedar-policy-core/src/entities/json) (entities and context), [validator/cedar_schema](cedar-policy-core/src/validator/cedar_schema) and [validator/json_schema.rs](cedar-policy-core/src/validator/json_schema.rs) (schemas) |
| Template linking | [ast/policy_set.rs](cedar-policy-core/src/ast/policy_set.rs) |
| Evaluator and authorizer | [evaluator.rs](cedar-policy-core/src/evaluator.rs), [authorizer.rs](cedar-policy-core/src/authorizer.rs) |
| Validator | [validator/typecheck](cedar-policy-core/src/validator/typecheck), [entities/conformance.rs](cedar-policy-core/src/entities/conformance.rs), [validator/coreschema.rs](cedar-policy-core/src/validator/coreschema.rs) |
| SymCC | [cedar-policy-symcc/src/symcc](cedar-policy-symcc/src/symcc) |
| Type-aware partial evaluation | [tpe](cedar-policy-core/src/tpe) |
| Language design: no I/O, clock, or randomness, a fixed set of extension functions, and `like` patterns instead of regular expressions | [extensions](cedar-policy-core/src/extensions), [ast/pattern.rs](cedar-policy-core/src/ast/pattern.rs) |
| Safe Rust: `unsafe_code = "forbid"` in every crate | [Cargo.toml](Cargo.toml) |

**Security relevant.** These are choices made by whoever deploys Cedar. They do not change whether Cedar computes decisions correctly, but they limit what untrusted input can do to the host.

* **Input size limits.** Cedar does not bound the size of its input. A service that accepts policies, schemas, entities, or requests from untrusted parties must set limits to protect against memory exhaustion.
* **Platform and stack size.** Where the `stacker` crate is supported, deeply nested input produces a `RecursionLimit` error, and callers can allow deeper input with `stacker::grow`. Wasm and Android have no such check, so deployments there should also bound nesting depth.
* **Cargo features.** The defaults enable only the `ipaddr`, `decimal`, and `datetime` extensions. Experimental features, such as TPE, entity manifests, and protobuf support, are off by default, and enabling one adds code that untrusted input can reach.
* **Solver.** SymCC runs whichever cvc5 binary the CLI's `--cvc5-path` option, the `CVC5` environment variable, or `PATH` names, so deployments should point it at a trusted cvc5 binary.

### Project compliance

Cedar does not claim compliance with any security standard. The project publishes an OpenSSF [Security Insights](security-insights.yml) file and is assessing itself against the OpenSSF OSPS Baseline.

### Secure development practices

#### Development pipeline

* **Review.** Changes to `main` and to release branches need two approving reviews. A DCO sign-off check runs on pull requests.
* **CI checks on every pull request.** Build, tests, Clippy, rustfmt, cargo-audit, cargo-deny, a minimum supported Rust version check, the Wasm build, cargo-semver-checks, and test coverage ([ci.yml](.github/workflows/ci.yml), [build_and_test.yml](.github/workflows/build_and_test.yml)).
* **Checks against related repositories on every pull request.** Builds of the differential testing harness and Lean bindings from cedar-spec, the integration test corpus, and the examples ([build_downstream_deps.yml](.github/workflows/build_downstream_deps.yml)).
* **Nightly.** The full build and test suite, a cargo-deny advisories check that opens an issue when it fails, and a cedar-java build ([nightly_build.yml](.github/workflows/nightly_build.yml), [cargo_audit.yml](.github/workflows/cargo_audit.yml), [nightly_build_downstream.yml](.github/workflows/nightly_build_downstream.yml)).
* **Repository scanning.** CodeQL default setup, OpenSSF Scorecard, Dependabot alerts and security updates, and secret scanning with push protection.
* **Verification.** Cedar follows [verification-guided development (VGD)](https://arxiv.org/abs/2407.01688), where a Lean model implementation precedes each language update. The Lean model and proofs live in [cedar-spec](https://github.com/cedar-policy/cedar-spec). Its [cedar-drt](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-drt) folder holds the differential and property-based fuzz targets. Long fuzzing runs happen on maintainer infrastructure outside GitHub. Their minimized corpus is published in [cedar-integration-tests](https://github.com/cedar-policy/cedar-integration-tests) and refreshed with each minor release.
* **Language changes.** Substantial changes to the language go through the [RFC process](https://github.com/cedar-policy/rfcs).

#### Communication channels

* **Internal.** Maintainers hold weekly meetings and communicate through Slack.
* **Inbound.** [GitHub issues](https://github.com/cedar-policy/cedar/issues), the [#cedar-general](https://cloud-native.slack.com/archives/C0AQXC9M4G1) channel on the CNCF Slack, and `cedar-policy-security@lists.cncf.io` for security reports.
* **Outbound.** [GitHub releases](https://github.com/cedar-policy/cedar/releases) and the changelogs, [security advisories](https://github.com/cedar-policy/cedar/security/advisories), the [Cedar blog](https://www.cedarpolicy.com/blog), and monthly meeting notes in [cedar-community](https://github.com/cedar-policy/cedar-community).

#### Ecosystem

Cedar is a CNCF Sandbox project. AWS uses it in Amazon Verified Permissions and AWS Verified Access ([Amazon Science](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)), and in Policy in Amazon Bedrock AgentCore ([AWS documentation](https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreatePolicy.html)). The cedar-policy organization also maintains Java bindings ([cedar-java](https://github.com/cedar-policy/cedar-java)), an independent Go implementation ([cedar-go](https://github.com/cedar-policy/cedar-go)) that also runs the integration test corpus, and a Kubernetes authorizer ([cedar-access-control-for-k8s](https://github.com/cedar-policy/cedar-access-control-for-k8s)). [cedar-awesome](https://github.com/cedar-policy/cedar-awesome) lists community bindings and tools.

### Security issue resolution

#### Responsible disclosure process

* **Reporting.** Reporters email `cedar-policy-security@lists.cncf.io`, as [SECURITY.md](SECURITY.md) describes, and do not open public issues. GitHub private vulnerability reporting is not enabled.
* **Response team.** Cedar maintainers read the security mailing list and assess the severity of each report.
* **Coordination.** The team acknowledges a report within 1 business day and gives an initial assessment within 5 business days. If the report is confirmed, the team agrees an embargo with the reporter, typically at least 2 weeks after any development time, and publishes the issue with its fix when the embargo ends.

#### Incident response

* **Triage and confirmation.** Maintainers try to reproduce the reported vulnerability, confirm it, and score its severity with CVSS.
* **Remediation.** In past advisories, a fixed version was released for every affected major version before the advisory was published.
* **Notification.** Maintainers publish a [GitHub security advisory](https://github.com/cedar-policy/cedar/security/advisories) that names the affected and patched versions of each package.

### Appendix

#### Known issues over time

See [security advisories](https://github.com/cedar-policy/cedar/security/advisories).

#### OpenSSF Best Practices

Cedar's [OpenSSF Best Practices](https://www.bestpractices.dev/projects/11398) entry is 87% of the way to the passing badge, and was last updated on 2025-10-27.

#### Case studies

Practical use cases can be found in [cedar-examples](https://github.com/cedar-policy/cedar-examples).

#### Related projects

Open Policy Agent's Rego and OpenFGA are the projects users most often compare with Cedar. The [Trail of Bits report](https://github.com/trailofbits/publications/blob/master/reports/Policy_Language_Security_Comparison_and_TM.pdf) compares the three by threat group, and the [OOPSLA 2024 paper](https://arxiv.org/abs/2403.04651) compares readability and performance.

#### Third-party security reviews

| Review | Date | Scope |
| -- | -- | -- |
| [Trail of Bits: Cedar, Rego, and OpenFGA Policy Languages, Comparative Language Security Assessment](https://github.com/trailofbits/publications/blob/master/reports/Policy_Language_Security_Comparison_and_TM.pdf) | 2024-08-21 | Threat model and comparison of Cedar 3.2.0, Rego 0.64.1, and OpenFGA 1.5.3, commissioned by AWS. It did not evaluate the Lean model. |
