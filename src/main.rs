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
    ChannelId, Client, Context, CreateWebhook, EventHandler, ExecuteWebhook, GatewayIntents, Http,
    Message as DiscordMessage, Ready, Webhook,
};
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
    channel_mappings: HashMap<u64, u64>,
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

    fn reverse_channel_mappings(&self) -> HashMap<u64, u64> {
        self.channel_mappings
            .iter()
            .map(|(&k, &v)| (v, k))
            .collect()
    }
}

type DiscourseWebhookKey = (String, u64);

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    http_client: reqwest::Client,
    discord_http: Arc<Http>,
    // Discord channel -> Discord webhook
    discord_webhooks: Arc<RwLock<HashMap<u64, Webhook>>>,
    // (username, discourse_channel_id) -> Discourse webhook URL
    discourse_webhooks: Arc<RwLock<HashMap<DiscourseWebhookKey, String>>>,
    // Discord channel ID -> Discourse channel ID
    reverse_mappings: Arc<HashMap<u64, u64>>,
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
    message: String,
    user: DiscourseUser,
    chat_webhook_event: Option<serde_json::Value>,
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

async fn send_to_discord(
    state: &AppState,
    discord_channel_id: u64,
    user: &DiscourseUser,
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let webhook = get_or_create_discord_webhook(state, discord_channel_id)
        .await
        .ok_or("Failed to get or create Discord webhook")?;

    let builder = ExecuteWebhook::new()
        .content(message)
        .username(&user.username)
        .avatar_url(build_avatar_url(
            &state.config.discourse_base_url,
            &user.avatar_template,
        ));

    webhook.execute(&state.discord_http, false, builder).await?;

    Ok(())
}

async fn get_or_create_discourse_webhook(
    state: &AppState,
    username: &str,
    discourse_channel_id: u64,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let key = (username.to_string(), discourse_channel_id);

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

    let webhook_name = format!("{}-{}", username, discourse_channel_id);

    for webhook in response.incoming_chat_webhooks {
        if webhook.name == webhook_name
            && webhook.chat_channel.id == discourse_channel_id
            && webhook.username.as_deref() == Some(username)
        {
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
            emoji: "",
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
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let webhook_url =
        get_or_create_discourse_webhook(state, username, discourse_channel_id).await?;

    #[derive(Serialize)]
    struct DiscourseMessageForm<'a> {
        text: &'a str,
    }

    state
        .http_client
        .put(&webhook_url)
        .form(&DiscourseMessageForm { text: message })
        .send()
        .await?
        .error_for_status()?;

    Ok(())
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

    tracing::info!(
        "[Discourse #{}] {}: {}",
        channel.title,
        msg.user.username,
        msg.message
    );

    let discord_channel_id = match state.config.channel_mappings.get(&channel.id) {
        Some(&id) => id,
        None => {
            tracing::debug!(
                "No Discord channel mapping for Discourse channel {}",
                channel.id
            );
            return StatusCode::OK;
        }
    };

    if let Err(e) = send_to_discord(&state, discord_channel_id, &msg.user, &msg.message).await {
        tracing::error!("Failed to send to Discord: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    StatusCode::OK
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

        if let Err(e) = send_to_discourse(
            &self.state,
            discourse_channel_id,
            &msg.author.name,
            &msg.content,
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

    let reverse_mappings = config.reverse_channel_mappings();
    let discord_http = Arc::new(Http::new(&config.discord_bot_token));

    let state = AppState {
        config: Arc::new(config),
        http_client: reqwest::Client::new(),
        discord_http: discord_http.clone(),
        discord_webhooks: Arc::new(RwLock::new(HashMap::new())),
        discourse_webhooks: Arc::new(RwLock::new(HashMap::new())),
        reverse_mappings: Arc::new(reverse_mappings),
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
