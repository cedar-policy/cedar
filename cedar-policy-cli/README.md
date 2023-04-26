# Cedar CLI

This package contains the CLI interface for Cedar.

For more information about the Cedar language/project, please take a look
at [cedarpolicy.com](https://www.cedarpolicy.com).
See also the [`cedar-policy`](../cedar-policy) package, which is the main public Rust API for
Cedar.

To build and run the CLI, try `cargo run -- --help`.

This app uses the annotation `@id("PID")` as a simple way to define policy ids.
This usage is not standard and annotations have custom use depending on the app.
