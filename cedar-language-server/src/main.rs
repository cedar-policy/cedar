/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use cedar_language_server::server::Backend;
use tower_lsp_server::{LspService, Server};
use tracing::info;

#[tokio::main]
async fn main() {
    let appender = tracing_appender::rolling::hourly("./logs", "server.log");
    let (writer, _guard) = tracing_appender::non_blocking(appender);

    tracing_subscriber::fmt().json().with_writer(writer).init();
    info!("Starting server.");

    let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());

    let (service, socket) = LspService::new(Backend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
