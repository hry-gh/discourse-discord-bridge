use std::collections::HashMap;
use std::sync::Arc;

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
use sha1::{Digest, Sha1};
use sha2::Sha256;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
struct Config {
    discord_bot_token: String,
    discourse_webhook_secret: String,
    discourse_base_url: String,
    discourse_api_username: String,
    discourse_api_key: String,
    listen_address: Option<String>,
    #[serde(default)]
    channel_mappings: HashMap<String, u64>,
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

type DiscourseWebhookKey = (String, u64);

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
    // (username, discourse_channel_id) -> Discourse webhook URL
    discourse_webhooks: Arc<RwLock<HashMap<DiscourseWebhookKey, String>>>,
    // Discourse message ID -> Discord message ID
    message_map: Arc<RwLock<HashMap<u64, u64>>>,
    // Discord user ID -> Discourse emoji name (already uploaded)
    user_emojis: Arc<RwLock<HashMap<u64, String>>>,
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
    chat_webhook_event: Option<serde_json::Value>,
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
    excerpt: String,
    user: DiscourseReplyUser,
}

#[derive(Debug, Deserialize)]
struct DiscourseReplyUser {
    username: String,
}

#[derive(Debug, Deserialize)]
struct DiscourseUser {
    username: String,
    avatar_template: String,
}

#[derive(Debug, Deserialize)]
struct DiscourseChannel {
    id: u64,
    title: String,
}

// Discourse webhook creation response
#[derive(Debug, Deserialize)]
struct DiscourseWebhookResponse {
    id: u64,
    url: String,
}

// Discourse list webhooks response
#[derive(Debug, Deserialize)]
struct DiscourseWebhooksListResponse {
    incoming_chat_webhooks: Vec<DiscourseIncomingWebhook>,
}

#[derive(Debug, Deserialize)]
struct DiscourseIncomingWebhook {
    #[allow(dead_code)]
    id: u64,
    name: String,
    url: String,
    username: Option<String>,
    chat_channel: DiscourseWebhookChannel,
}

#[derive(Debug, Deserialize)]
struct DiscourseWebhookChannel {
    id: u64,
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
        .replace("@everyone", "@\u{200B}everyone")
        .replace("@here", "@\u{200B}here")
        // Role mentions: <@&ROLE_ID>
        .replace("<@&", "<@\u{200B}&")
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
        format!(
            "> **@{}:** {}\n{}",
            reply.user.username, reply.excerpt, message
        )
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
        let mut message_map = state.message_map.write().await;
        message_map.insert(discourse_message_id, discord_message.id.get());
        tracing::debug!(
            "Mapped Discourse message {} -> Discord message {}",
            discourse_message_id,
            discord_message.id
        );
    }

    Ok(())
}

async fn get_or_create_discourse_webhook(
    state: &AppState,
    username: &str,
    emoji_name: &str,
    discourse_channel_id: u64,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let webhook_name = format!("{}-{}-{}", username, emoji_name, discourse_channel_id);
    let key = (webhook_name.clone(), discourse_channel_id);

    {
        let webhooks = state.discourse_webhooks.read().await;
        if let Some(url) = webhooks.get(&key) {
            return Ok(url.clone());
        }
    }

    // Try to find existing webhook
    let list_url = format!(
        "{}/admin/plugins/chat/hooks.json",
        state.config.discourse_base_url
    );
    let response: DiscourseWebhooksListResponse = state
        .http_client
        .get(&list_url)
        .header("Api-Username", &state.config.discourse_api_username)
        .header("Api-Key", &state.config.discourse_api_key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    for webhook in response.incoming_chat_webhooks {
        if webhook.name == webhook_name && webhook.chat_channel.id == discourse_channel_id {
            let mut webhooks = state.discourse_webhooks.write().await;
            webhooks.insert(key, webhook.url.clone());
            return Ok(webhook.url);
        }
    }

    let create_url = format!(
        "{}/admin/plugins/chat/hooks",
        state.config.discourse_base_url
    );

    #[derive(Serialize)]
    struct CreateWebhookForm<'a> {
        name: &'a str,
        username: &'a str,
        chat_channel_id: u64,
    }

    let response: DiscourseWebhookResponse = state
        .http_client
        .post(&create_url)
        .header("Api-Username", &state.config.discourse_api_username)
        .header("Api-Key", &state.config.discourse_api_key)
        .form(&CreateWebhookForm {
            name: &webhook_name,
            username,
            chat_channel_id: discourse_channel_id,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let update_url = format!(
        "{}/admin/plugins/chat/hooks/{}",
        state.config.discourse_base_url, response.id
    );

    #[derive(Serialize)]
    struct UpdateWebhookForm<'a> {
        name: &'a str,
        username: &'a str,
        chat_channel_id: u64,
        description: &'a str,
        emoji: &'a str,
    }

    state
        .http_client
        .put(&update_url)
        .header("Api-Username", &state.config.discourse_api_username)
        .header("Api-Key", &state.config.discourse_api_key)
        .form(&UpdateWebhookForm {
            name: &webhook_name,
            username,
            chat_channel_id: discourse_channel_id,
            description: "",
            emoji: emoji_name,
        })
        .send()
        .await?
        .error_for_status()?;

    let mut webhooks = state.discourse_webhooks.write().await;
    webhooks.insert(key, response.url.clone());
    Ok(response.url)
}

async fn send_to_discourse(
    state: &AppState,
    discourse_channel_id: u64,
    username: &str,
    emoji_name: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let webhook_url =
        get_or_create_discourse_webhook(state, username, emoji_name, discourse_channel_id).await?;

    #[derive(Serialize)]
    struct DiscourseMessageForm<'a> {
        text: &'a str,
    }

    let response = state
        .http_client
        .post(&webhook_url)
        .form(&DiscourseMessageForm { text: message })
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!(
            "Discourse webhook failed: status={}, url={}, username={}, message={:?}, response={}",
            status,
            webhook_url,
            username,
            message,
            body
        );
        return Err(format!("Discourse webhook failed: {} - {}", status, body).into());
    }

    Ok(())
}

async fn ensure_user_emoji(
    state: &AppState,
    user_id: u64,
    avatar_url: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    {
        let emojis = state.user_emojis.read().await;
        if let Some(emoji_name) = emojis.get(&user_id) {
            return Ok(emoji_name.clone());
        }
    }

    let emoji_name = avatar_url
        .split('/')
        .next_back()
        .and_then(|s| s.split('?').next())
        .and_then(|s| {
            s.strip_suffix(".webp")
                .or_else(|| s.strip_suffix(".png"))
                .or_else(|| s.strip_suffix(".gif"))
        })
        .unwrap_or("avatar")
        .to_string();

    let avatar_bytes = state
        .http_client
        .get(avatar_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let mut hasher = Sha1::new();
    hasher.update(&avatar_bytes);
    let sha1_checksum = hex::encode(hasher.finalize());

    let content_type = if avatar_url.contains(".webp") {
        "image/webp"
    } else if avatar_url.contains(".gif") {
        "image/gif"
    } else {
        "image/png"
    };

    let upload_url = format!(
        "{}/admin/config/emoji.json",
        state.config.discourse_base_url
    );

    let form = reqwest::multipart::Form::new()
        .text("upload_type", "emoji")
        .text("name", emoji_name.clone())
        .text("type", content_type.to_string())
        .text("group", "user")
        .text("sha1_checksum", sha1_checksum)
        .part(
            "file",
            reqwest::multipart::Part::bytes(avatar_bytes.to_vec())
                .file_name(format!("{}.webp", emoji_name))
                .mime_str(content_type)?,
        );

    let response = state
        .http_client
        .post(&upload_url)
        .header("Api-Username", &state.config.discourse_api_username)
        .header("Api-Key", &state.config.discourse_api_key)
        .multipart(form)
        .send()
        .await?;

    let emoji_created = if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if body.contains("already been taken") || body.contains("already exists") {
            tracing::debug!("Emoji {} already exists", emoji_name);
            false
        } else {
            tracing::warn!(
                "Failed to upload emoji {}: {} - {}",
                emoji_name,
                status,
                body
            );
            false
        }
    } else {
        tracing::info!("Uploaded emoji {} for user {}", emoji_name, user_id);
        true
    };

    if emoji_created {
        let deny_list_url = format!(
            "{}/admin/site_settings/emoji_deny_list",
            state.config.discourse_base_url
        );

        let response = state
            .http_client
            .put(&deny_list_url)
            .header("Api-Username", &state.config.discourse_api_username)
            .header("Api-Key", &state.config.discourse_api_key)
            .form(&[("emoji_deny_list", &emoji_name)])
            .send()
            .await;

        match response {
            Ok(r) if r.status().is_success() => {
                tracing::debug!("Added emoji {} to deny list", emoji_name);
            }
            Ok(r) => {
                let body = r.text().await.unwrap_or_default();
                tracing::warn!("Failed to add emoji {} to deny list: {}", emoji_name, body);
            }
            Err(e) => {
                tracing::warn!("Failed to add emoji {} to deny list: {}", emoji_name, e);
            }
        }
    }

    let mut emojis = state.user_emojis.write().await;
    emojis.insert(user_id, emoji_name.clone());

    Ok(emoji_name)
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

    if msg.chat_webhook_event.is_some() {
        return StatusCode::OK;
    }

    if msg.user.username == "system" {
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
        let message_map = state.message_map.read().await;
        match message_map.get(&discourse_message_id) {
            Some(&id) => id,
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
        let mut message_map = state.message_map.write().await;
        match message_map.remove(&discourse_message_id) {
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

        let mut content = if let Some(ref reply) = msg.referenced_message {
            format!(
                "> **@{}:** {}\n\n{}",
                reply.author.name, reply.content, msg.content
            )
        } else {
            msg.content.clone()
        };

        // Append attachment URLs
        for attachment in &msg.attachments {
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&attachment.url);
        }

        // Skip empty messages
        if content.is_empty() {
            return;
        }

        // Upload user's avatar as emoji if needed
        let emoji_name = if let Some(avatar_url) = msg.author.avatar_url() {
            match ensure_user_emoji(&self.state, msg.author.id.get(), &avatar_url).await {
                Ok(name) => name,
                Err(e) => {
                    tracing::warn!("Failed to upload user emoji: {}", e);
                    String::new()
                }
            }
        } else {
            String::new()
        };

        if let Err(e) = send_to_discourse(
            &self.state,
            discourse_channel_id,
            &msg.author.name,
            &emoji_name,
            &content,
        )
        .await
        {
            tracing::error!("Failed to send to Discourse: {}", e);
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

    let state = AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        discord_http: discord_http.clone(),
        channel_mappings: Arc::new(channel_mappings),
        reverse_mappings: Arc::new(reverse_mappings),
        discord_webhooks: Arc::new(RwLock::new(HashMap::new())),
        discourse_webhooks: Arc::new(RwLock::new(HashMap::new())),
        message_map: Arc::new(RwLock::new(HashMap::new())),
        user_emojis: Arc::new(RwLock::new(HashMap::new())),
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
