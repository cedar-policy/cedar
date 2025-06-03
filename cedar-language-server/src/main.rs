use cedar_language_server::server::Backend;
use tower_lsp::{LspService, Server};
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
