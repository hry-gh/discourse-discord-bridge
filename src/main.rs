use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::Connection;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serenity::all::{
    ChannelId, Client, Context, CreateWebhook, EditWebhookMessage, EventHandler, ExecuteWebhook,
    GatewayIntents, Http, Message as DiscordMessage, MessageId, Ready, Webhook,
};
use sha2::Sha256;
use tokio::sync::{Mutex, RwLock};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
struct Config {
    discord_bot_token: String,
    discourse_webhook_secret: String,
    discourse_base_url: String,
    discourse_mirror_url: String,
    listen_address: Option<String>,
    #[serde(default = "default_database_path")]
    database_path: String,
    #[serde(default)]
    channel_mappings: HashMap<String, u64>,
}

fn default_database_path() -> String {
    if std::path::Path::new("/data").exists() {
        "/data/messages.db".to_string()
    } else {
        "messages.db".to_string()
    }
}

impl Config {
    fn load() -> Self {
        let config_path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "config.toml".to_string());

        let content = std::fs::read_to_string(&config_path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path, e));

        toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse {}: {}", config_path, e))
    }

    fn channel_mappings_parsed(&self) -> HashMap<u64, u64> {
        self.channel_mappings
            .iter()
            .filter_map(|(k, &v)| k.parse::<u64>().ok().map(|k| (k, v)))
            .collect()
    }

    fn reverse_channel_mappings(&self) -> HashMap<u64, u64> {
        self.channel_mappings
            .iter()
            .filter_map(|(k, &v)| k.parse::<u64>().ok().map(|k| (v, k)))
            .collect()
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    http_client: reqwest::Client,
    discord_http: Arc<Http>,
    // Discourse channel ID -> Discord channel ID
    channel_mappings: Arc<HashMap<u64, u64>>,
    // Discord channel ID -> Discourse channel ID
    reverse_mappings: Arc<HashMap<u64, u64>>,
    // Discord channel -> Discord webhook
    discord_webhooks: Arc<RwLock<HashMap<u64, Webhook>>>,
    // SQLite database for message ID mappings
    db: Arc<Mutex<Connection>>,
}

// Discourse -> Discord types
#[derive(Debug, Deserialize)]
struct DiscourseWebhookPayload {
    chat_message: DiscourseChatMessage,
}

#[derive(Debug, Deserialize)]
struct DiscourseChatMessage {
    message: DiscourseMessage,
    channel: DiscourseChannel,
}

#[derive(Debug, Deserialize)]
struct DiscourseMessage {
    id: u64,
    message: String,
    user: DiscourseUser,
    in_reply_to: Option<DiscourseReplyInfo>,
    #[serde(default)]
    uploads: Vec<DiscourseUpload>,
}

#[derive(Debug, Deserialize)]
struct DiscourseUpload {
    url: String,
}

#[derive(Debug, Deserialize)]
struct DiscourseReplyInfo {
    id: u64,
    cooked: String,
    user: DiscourseReplyUser,
    chat_webhook_event: Option<DiscourseWebhookEvent>,
}

#[derive(Debug, Deserialize)]
struct DiscourseReplyUser {
    username: String,
}

#[derive(Debug, Deserialize)]
struct DiscourseWebhookEvent {
    username: String,
}

#[derive(Debug, Deserialize)]
struct DiscourseUser {
    id: i64,
    username: String,
    avatar_template: String,
}

#[derive(Debug, Deserialize)]
struct DiscourseChannel {
    id: u64,
    title: String,
}

fn init_database(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS message_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            source_id INTEGER NOT NULL,
            target_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            UNIQUE(source, source_id)
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_source ON message_links(source, source_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_target ON message_links(source, target_id)",
        [],
    )?;
    Ok(conn)
}

fn store_message_link(
    conn: &Connection,
    source: &str,
    source_id: u64,
    target_id: u64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO message_links (source, source_id, target_id) VALUES (?1, ?2, ?3)",
        rusqlite::params![source, source_id as i64, target_id as i64],
    )?;
    Ok(())
}

fn get_discord_message_id(conn: &Connection, discourse_id: u64) -> Option<u64> {
    conn.query_row(
        "SELECT target_id FROM message_links WHERE source = 'discourse' AND source_id = ?1",
        rusqlite::params![discourse_id as i64],
        |row| row.get::<_, i64>(0),
    )
    .ok()
    .map(|id| id as u64)
}

fn get_discourse_message_id(conn: &Connection, discord_id: u64) -> Option<u64> {
    conn.query_row(
        "SELECT target_id FROM message_links WHERE source = 'discord' AND source_id = ?1",
        rusqlite::params![discord_id as i64],
        |row| row.get::<_, i64>(0),
    )
    .ok()
    .map(|id| id as u64)
}

fn verify_signature(secret: &str, body: &[u8], signature_header: &str) -> bool {
    let expected_signature = match signature_header.strip_prefix("sha256=") {
        Some(sig) => sig,
        None => return false,
    };

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };

    mac.update(body);
    let result = hex::encode(mac.finalize().into_bytes());

    result == expected_signature
}

fn build_avatar_url(base_url: &str, avatar_template: &str) -> String {
    let path = avatar_template.replace("{size}", "128");
    format!("{}{}", base_url, path)
}

fn decode_html_entities(s: &str) -> String {
    s.replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn extract_reply_content(cooked: &str) -> String {
    // Strip <blockquote>...</blockquote> only at the beginning of cooked HTML
    static BLOCKQUOTE_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?s)^<blockquote>.*?</blockquote>\n?").unwrap());
    let without_blockquote = BLOCKQUOTE_RE.replace(cooked, "");

    // Strip HTML tags and convert to plain text
    static HTML_TAG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<[^>]+>").unwrap());
    let plain = HTML_TAG_RE.replace_all(&without_blockquote, "");

    decode_html_entities(plain.trim())
}

fn strip_discord_reply_prefix(content: &str) -> String {
    static REPLY_PREFIX_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^↩️ \[[^\]]+\]\([^)]+\): [^\n]*\n").unwrap());

    static BLOCKQUOTE_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^> \*\*[^*]+:\*\* [^\n]*\n").unwrap());

    let content = REPLY_PREFIX_RE.replace(content, "");
    BLOCKQUOTE_RE.replace(&content, "").to_string()
}

fn resolve_discord_mentions(content: &str, msg: &DiscordMessage) -> String {
    let mut result = content.to_string();
    for user in &msg.mentions {
        let mention_pattern = format!("<@{}>", user.id);
        let mention_pattern_nick = format!("<@!{}>", user.id);
        // Use full-width @ to prevent pinging on Discourse
        let replacement = format!("＠{}", user.name);
        result = result.replace(&mention_pattern, &replacement);
        result = result.replace(&mention_pattern_nick, &replacement);
    }
    result
}

async fn get_or_create_discord_webhook(
    state: &AppState,
    discord_channel_id: u64,
) -> Option<Webhook> {
    {
        let webhooks = state.discord_webhooks.read().await;
        if let Some(webhook) = webhooks.get(&discord_channel_id) {
            return Some(webhook.clone());
        }
    }

    let channel_id = ChannelId::new(discord_channel_id);
    let existing_webhooks = channel_id.webhooks(&state.discord_http).await.ok()?;
    let current_user_id = state.discord_http.get_current_user().await.ok()?.id;

    for webhook in existing_webhooks {
        if webhook.user.as_ref().map(|u| u.id) == Some(current_user_id) {
            let mut webhooks = state.discord_webhooks.write().await;
            webhooks.insert(discord_channel_id, webhook.clone());
            return Some(webhook);
        }
    }

    let builder = CreateWebhook::new("Discourse Bridge");
    let webhook = channel_id
        .create_webhook(&state.discord_http, builder)
        .await
        .ok()?;

    let mut webhooks = state.discord_webhooks.write().await;
    webhooks.insert(discord_channel_id, webhook.clone());
    Some(webhook)
}

fn sanitize_discord_message(message: &str) -> String {
    message
        .replace("@everyone", "＠everyone")
        .replace("@here", "＠here")
        // Role mentions: <@&ROLE_ID>
        .replace("<@&", "<＠&")
}

async fn send_to_discord(
    state: &AppState,
    discord_channel_id: u64,
    discourse_message_id: u64,
    user: &DiscourseUser,
    message: &str,
    reply_to: Option<&DiscourseReplyInfo>,
    uploads: &[DiscourseUpload],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let webhook = get_or_create_discord_webhook(state, discord_channel_id)
        .await
        .ok_or("Failed to get or create Discord webhook")?;

    let mut content = if let Some(reply) = reply_to {
        let username = reply
            .chat_webhook_event
            .as_ref()
            .map(|e| e.username.as_str())
            .unwrap_or(&reply.user.username);
        let reply_content = strip_discord_reply_prefix(&extract_reply_content(&reply.cooked));

        let db = state.db.lock().await;
        let reply_link = get_discord_message_id(&db, reply.id).map(|discord_msg_id| {
            format!(
                "https://discord.com/channels/{}/{}",
                discord_channel_id, discord_msg_id
            )
        });
        drop(db);

        if let Some(link) = reply_link {
            format!(
                "↩️ [{}]({}): {}\n{}",
                username, link, reply_content, message
            )
        } else {
            format!("> **{}:** {}\n{}", username, reply_content, message)
        }
    } else {
        message.to_string()
    };

    for upload in uploads {
        if !content.is_empty() {
            content.push('\n');
        }

        if upload.url.starts_with("http://") || upload.url.starts_with("https://") {
            content.push_str(&upload.url);
        } else {
            content.push_str(&state.config.discourse_base_url);
            content.push_str(&upload.url);
        }
    }

    let sanitized = sanitize_discord_message(&content);

    let builder = ExecuteWebhook::new()
        .content(&sanitized)
        .username(&user.username)
        .avatar_url(build_avatar_url(
            &state.config.discourse_base_url,
            &user.avatar_template,
        ));

    if let Some(discord_message) = webhook.execute(&state.discord_http, true, builder).await? {
        let db = state.db.lock().await;
        if let Err(e) = store_message_link(
            &db,
            "discourse",
            discourse_message_id,
            discord_message.id.get(),
        ) {
            tracing::warn!("Failed to store message link: {}", e);
        }
        tracing::debug!(
            "Mapped Discourse message {} -> Discord message {}",
            discourse_message_id,
            discord_message.id
        );
    }

    Ok(())
}

async fn send_to_discourse(
    state: &AppState,
    discourse_channel_id: u64,
    discord_message_id: u64,
    discord_user_id: u64,
    discord_username: &str,
    discord_avatar_url: Option<String>,
    message: &str,
    reply_to_message_id: Option<u64>,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    #[derive(Serialize)]
    struct DiscordUser<'a> {
        id: String,
        username: &'a str,
        avatar_url: Option<String>,
    }

    #[derive(Serialize)]
    struct MessagePayload<'a> {
        content: &'a str,
    }

    #[derive(Serialize)]
    struct MirrorPayload<'a> {
        channel_id: u64,
        discord_user: DiscordUser<'a>,
        message: MessagePayload<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reply_to_message_id: Option<u64>,
    }

    #[derive(Deserialize)]
    struct MirrorResponse {
        discourse_message_id: u64,
    }

    let payload = MirrorPayload {
        channel_id: discourse_channel_id,
        discord_user: DiscordUser {
            id: discord_user_id.to_string(),
            username: discord_username,
            avatar_url: discord_avatar_url,
        },
        message: MessagePayload { content: message },
        reply_to_message_id,
    };

    let response = state
        .http_client
        .post(&state.config.discourse_mirror_url)
        .json(&payload)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!(
            "Discourse mirror failed: status={}, username={}, message={:?}, response={}",
            status,
            discord_username,
            message,
            body
        );
        return Err(format!("Discourse mirror failed: {} - {}", status, body).into());
    }

    let result: MirrorResponse = response.json().await?;

    let db = state.db.lock().await;
    if let Err(e) = store_message_link(
        &db,
        "discord",
        discord_message_id,
        result.discourse_message_id,
    ) {
        tracing::warn!("Failed to store message link: {}", e);
    }
    tracing::debug!(
        "Mapped Discord message {} -> Discourse message {}",
        discord_message_id,
        result.discourse_message_id
    );

    Ok(result.discourse_message_id)
}

async fn handle_discourse_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let signature = match headers.get("x-discourse-event-signature") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s,
            Err(_) => return StatusCode::BAD_REQUEST,
        },
        None => return StatusCode::UNAUTHORIZED,
    };

    if !verify_signature(&state.config.discourse_webhook_secret, &body, signature) {
        tracing::warn!("Invalid webhook signature");
        return StatusCode::UNAUTHORIZED;
    }

    let event_type = headers
        .get("x-discourse-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("chat_message_created");

    let payload: DiscourseWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to parse webhook payload: {}", e);
            return StatusCode::BAD_REQUEST;
        }
    };

    let msg = &payload.chat_message.message;
    let channel = &payload.chat_message.channel;

    if msg.user.id < 0 {
        return StatusCode::OK;
    }

    let discord_channel_id = match state.channel_mappings.get(&channel.id) {
        Some(&id) => id,
        None => {
            tracing::debug!(
                "No Discord channel mapping for Discourse channel {}",
                channel.id
            );
            return StatusCode::OK;
        }
    };

    match event_type {
        "chat_message_created" => {
            tracing::info!(
                "[Discourse #{}] {}: {}",
                channel.title,
                msg.user.username,
                msg.message
            );

            if let Err(e) = send_to_discord(
                &state,
                discord_channel_id,
                msg.id,
                &msg.user,
                &msg.message,
                msg.in_reply_to.as_ref(),
                &msg.uploads,
            )
            .await
            {
                tracing::error!("Failed to send to Discord: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        "chat_message_edited" => {
            tracing::info!(
                "[Discourse #{}] {} edited: {}",
                channel.title,
                msg.user.username,
                msg.message
            );

            if let Err(e) = edit_discord_message(
                &state,
                discord_channel_id,
                msg.id,
                &msg.message,
                &msg.uploads,
            )
            .await
            {
                tracing::error!("Failed to edit Discord message: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        "chat_message_trashed" => {
            tracing::info!(
                "[Discourse #{}] {} deleted message {}",
                channel.title,
                msg.user.username,
                msg.id
            );

            if let Err(e) = delete_discord_message(&state, discord_channel_id, msg.id).await {
                tracing::error!("Failed to delete Discord message: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        _ => {
            tracing::debug!("Ignoring unknown event type: {}", event_type);
        }
    }

    StatusCode::OK
}

async fn edit_discord_message(
    state: &AppState,
    discord_channel_id: u64,
    discourse_message_id: u64,
    message: &str,
    uploads: &[DiscourseUpload],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let discord_message_id = {
        let db = state.db.lock().await;
        match get_discord_message_id(&db, discourse_message_id) {
            Some(id) => id,
            None => {
                tracing::debug!(
                    "No Discord message ID found for Discourse message {}",
                    discourse_message_id
                );
                return Ok(());
            }
        }
    };

    let webhook = get_or_create_discord_webhook(state, discord_channel_id)
        .await
        .ok_or("Failed to get Discord webhook")?;

    let mut content = message.to_string();

    for upload in uploads {
        if !content.is_empty() {
            content.push('\n');
        }
        if upload.url.starts_with("http://") || upload.url.starts_with("https://") {
            content.push_str(&upload.url);
        } else {
            content.push_str(&state.config.discourse_base_url);
            content.push_str(&upload.url);
        }
    }

    let sanitized = sanitize_discord_message(&content);

    let builder = EditWebhookMessage::new().content(&sanitized);

    webhook
        .edit_message(
            &state.discord_http,
            MessageId::new(discord_message_id),
            builder,
        )
        .await?;

    Ok(())
}

async fn delete_discord_message(
    state: &AppState,
    discord_channel_id: u64,
    discourse_message_id: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let discord_message_id = {
        let db = state.db.lock().await;
        match get_discord_message_id(&db, discourse_message_id) {
            Some(id) => id,
            None => {
                tracing::debug!(
                    "No Discord message ID found for Discourse message {}",
                    discourse_message_id
                );
                return Ok(());
            }
        }
    };

    let webhook = get_or_create_discord_webhook(state, discord_channel_id)
        .await
        .ok_or("Failed to get Discord webhook")?;

    webhook
        .delete_message(
            &state.discord_http,
            None,
            MessageId::new(discord_message_id),
        )
        .await?;

    Ok(())
}

struct DiscordHandler {
    state: AppState,
}

#[serenity::async_trait]
impl EventHandler for DiscordHandler {
    async fn ready(&self, _ctx: Context, ready: Ready) {
        tracing::info!("Discord bot connected as {}", ready.user.name);
    }

    async fn message(&self, _ctx: Context, msg: DiscordMessage) {
        if msg.author.bot {
            return;
        }

        let discord_channel_id = msg.channel_id.get();

        let discourse_channel_id = match self.state.reverse_mappings.get(&discord_channel_id) {
            Some(&id) => id,
            None => return,
        };

        tracing::info!(
            "[Discord #{}] {}: {}",
            discord_channel_id,
            msg.author.name,
            msg.content
        );

        let reply_to_discourse_id = if let Some(ref reply) = msg.referenced_message {
            let db = self.state.db.lock().await;
            get_discourse_message_id(&db, reply.id.get())
        } else {
            None
        };

        let mut content = msg.content.clone();

        for attachment in &msg.attachments {
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&attachment.url);
        }

        let content = resolve_discord_mentions(&content, &msg);

        if content.is_empty() {
            return;
        }

        match send_to_discourse(
            &self.state,
            discourse_channel_id,
            msg.id.get(),
            msg.author.id.get(),
            &msg.author.name,
            msg.author.avatar_url(),
            &content,
            reply_to_discourse_id,
        )
        .await
        {
            Ok(discourse_message_id) => {
                tracing::debug!("Sent to Discourse: message_id={}", discourse_message_id);
            }
            Err(e) => {
                tracing::error!("Failed to send to Discourse: {}", e);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = Config::load();
    let listen_address = config
        .listen_address
        .clone()
        .unwrap_or_else(|| "0.0.0.0:3000".to_string());

    let channel_mappings = config.channel_mappings_parsed();
    let reverse_mappings = config.reverse_channel_mappings();
    let discord_http = Arc::new(Http::new(&config.discord_bot_token));

    let db = init_database(&config.database_path).expect("Failed to initialize database");
    tracing::info!("Using database: {}", config.database_path);

    let state = AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        discord_http: discord_http.clone(),
        channel_mappings: Arc::new(channel_mappings),
        reverse_mappings: Arc::new(reverse_mappings),
        discord_webhooks: Arc::new(RwLock::new(HashMap::new())),
        db: Arc::new(Mutex::new(db)),
    };

    let handler = DiscordHandler {
        state: state.clone(),
    };

    let intents = GatewayIntents::GUILD_MESSAGES | GatewayIntents::MESSAGE_CONTENT;
    let mut discord_client = Client::builder(&state.config.discord_bot_token, intents)
        .event_handler(handler)
        .await
        .expect("Failed to create Discord client");

    let app = Router::new()
        .route("/webhook", post(handle_discourse_webhook))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_address)
        .await
        .unwrap();
    tracing::info!("Listening on {}", listener.local_addr().unwrap());

    tokio::select! {
        result = discord_client.start() => {
            if let Err(e) = result {
                tracing::error!("Discord client error: {}", e);
            }
        }
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                tracing::error!("Axum server error: {}", e);
            }
        }
    }
}
