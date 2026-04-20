use clap::Parser;
use color_eyre::eyre::Context;
use ratatui::{
    Terminal, TerminalOptions, Viewport,
    backend::CrosstermBackend,
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph},
};
use russh::{
    Channel, ChannelId, Pty,
    keys::{
        Algorithm, PrivateKey,
        ssh_key::{LineEnding, PublicKey},
    },
    server::*,
};
use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{
    Mutex,
    mpsc::{UnboundedSender, unbounded_channel},
};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

type SshTerminal = Terminal<CrosstermBackend<TerminalHandle>>;

struct App {
    pub counter: usize,
}

impl App {
    pub fn new() -> App {
        Self { counter: 0 }
    }
}

struct TerminalHandle {
    sender: UnboundedSender<Vec<u8>>,
    // The sink collects the data which is finally sent to sender.
    sink: Vec<u8>,
}

impl TerminalHandle {
    async fn start(handle: Handle, channel_id: ChannelId) -> Self {
        let (sender, mut receiver) = unbounded_channel::<Vec<u8>>();
        tokio::spawn(async move {
            while let Some(data) = receiver.recv().await {
                let result = handle.data(channel_id, data).await;
                if result.is_err() {
                    eprintln!("Failed to send data: {result:?}");
                }
            }
        });
        Self {
            sender,
            sink: Vec::new(),
        }
    }
}

// The crossterm backend writes to the terminal handle.
impl io::Write for TerminalHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sink.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.sender
            .send(self.sink.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
        self.sink.clear();
        Ok(())
    }
}

#[derive(Clone)]
struct AppServer {
    clients: Arc<Mutex<HashMap<usize, (SshTerminal, App)>>>,
    id: usize,
    private_key: PrivateKey,
}

/// Load from given path or generate (there) if it doesn't exist.
fn load_or_generate_private_key(path: &Path) -> color_eyre::Result<PrivateKey> {
    if path.exists() {
        info!("Loading host key from {}", path.display());
        let loaded_key =
            PrivateKey::read_openssh_file(path).wrap_err("Failed to read host key from file")?;
        return Ok(loaded_key);
    }
    info!(
        "Host key not found at '{}'. Generating new host key",
        path.display()
    );
    let generated_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .wrap_err("Failed to generate host key")?;
    generated_key
        .write_openssh_file(path, LineEnding::LF)
        .wrap_err("Failed to write host key to file")?;
    Ok(generated_key)
}

impl AppServer {
    pub fn new(private_key_path: &Path) -> color_eyre::Result<Self> {
        let private_key = load_or_generate_private_key(private_key_path)?;
        Ok(Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
            private_key,
        })
    }

    pub async fn run(
        &mut self,
        listen_addr: impl tokio::net::ToSocketAddrs + Send + Debug,
    ) -> color_eyre::Result<()> {
        let clients = self.clients.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                for (_, (terminal, app)) in clients.lock().await.iter_mut() {
                    app.counter += 1;

                    terminal
                        .draw(|f| {
                            let area = f.area();
                            f.render_widget(Clear, area);
                            let style = match app.counter % 3 {
                                0 => Style::default().fg(Color::Red),
                                1 => Style::default().fg(Color::Green),
                                _ => Style::default().fg(Color::Blue),
                            };
                            let paragraph = Paragraph::new(format!("Counter: {}", app.counter))
                                .alignment(ratatui::layout::Alignment::Center)
                                .style(style);
                            let block = Block::default()
                                .title("Press 'c' to reset the counter!")
                                .borders(Borders::ALL);
                            f.render_widget(paragraph.block(block), area);
                        })
                        .unwrap();
                }
            }
        });

        let config = Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            auth_rejection_time: std::time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            keys: vec![self.private_key.clone()],
            nodelay: true,
            ..Default::default()
        };

        info!("Starting SSH server on {:?}", listen_addr);
        self.run_on_address(config.into(), listen_addr).await?;
        Ok(())
    }
}

impl Server for AppServer {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
}

impl Handler for AppServer {
    type Error = color_eyre::Report;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let terminal_handle = TerminalHandle::start(session.handle(), channel.id()).await;

        let backend = CrosstermBackend::new(terminal_handle);

        // the correct viewport area will be set when the client request a pty
        let options = TerminalOptions {
            viewport: Viewport::Fixed(Rect::default()),
        };

        let terminal = Terminal::with_options(backend, options)?;
        let app = App::new();

        let mut clients = self.clients.lock().await;
        clients.insert(self.id, (terminal, app));

        Ok(true)
    }

    async fn auth_publickey(&mut self, _: &str, _: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match data {
            // Pressing 'q' closes the connection.
            b"q" => {
                self.clients.lock().await.remove(&self.id);
                session.close(channel)?;
            }
            // Pressing 'c' resets the counter for the app.
            // Only the client with the id sees the counter reset.
            b"c" => {
                let mut clients = self.clients.lock().await;
                let (_, app) = clients.get_mut(&self.id).unwrap();
                app.counter = 0;
            }
            _ => {}
        }

        Ok(())
    }

    /// The client's window size has changed.
    async fn window_change_request(
        &mut self,
        _: ChannelId,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        let rect = Rect {
            x: 0,
            y: 0,
            width: col_width as u16,
            height: row_height as u16,
        };

        let mut clients = self.clients.lock().await;
        let (terminal, _) = clients.get_mut(&self.id).unwrap();
        terminal.resize(rect)?;

        Ok(())
    }

    /// The client requests a pseudo-terminal with the given
    /// specifications.
    ///
    /// **Note:** Success or failure should be communicated to the client by calling
    /// `session.channel_success(channel)` or `session.channel_failure(channel)` respectively.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        col_width: u32,
        row_height: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let rect = Rect {
            x: 0,
            y: 0,
            width: col_width as u16,
            height: row_height as u16,
        };

        let mut clients = self.clients.lock().await;
        let (terminal, _) = clients.get_mut(&self.id).unwrap();
        terminal.resize(rect)?;

        session.channel_success(channel)?;

        Ok(())
    }
}

impl Drop for AppServer {
    fn drop(&mut self) {
        let id = self.id;
        let clients = self.clients.clone();
        tokio::spawn(async move {
            let mut clients = clients.lock().await;
            clients.remove(&id);
        });
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "ssh_host_ed25519_key")]
    host_key_file: PathBuf,

    #[arg(short, long, default_value = "0.0.0.0:2222")]
    listen_addr: String,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args = Args::parse();
    let listen_addr: SocketAddr = args.listen_addr.parse()?;

    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env()?,
        )
        .init();

    let mut server = AppServer::new(&args.host_key_file)?;
    server.run(listen_addr).await?;

    Ok(())
}
