//! AI chat streaming routes.

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
    routing::post,
    Json, Router,
};
use futures_util::StreamExt;
use genai::chat::{ContentPart, MessageContent};
use genai::chat::ChatMessage;
use serde::Deserialize;

use crate::auth::extractor::RequireAuth;
use crate::common::ApiError;
use crate::AppState;

/// A content part: text or base64-encoded attachment (image, PDF).
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPartDto {
    Text { text: String },
    Image {
        content_type: String,
        base64: String,
        #[serde(default)]
        name: Option<String>,
    },
    /// PDF or other binary; uses application/pdf typically.
    File {
        content_type: String,
        base64: String,
        #[serde(default)]
        name: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
pub struct ChatMessageDto {
    pub role: String,
    /// Plain text content (used when content_parts is absent).
    #[serde(default)]
    pub content: Option<String>,
    /// Multipart content: text + attachments. Takes precedence over content when present.
    #[serde(default)]
    pub content_parts: Option<Vec<ContentPartDto>>,
}

#[derive(Debug, Deserialize)]
pub struct ChatStreamRequest {
    pub model: String,
    pub messages: Vec<ChatMessageDto>,
}

fn content_part_dto_to_genai(dto: &ContentPartDto) -> Result<ContentPart, ApiError> {
    Ok(match dto {
        ContentPartDto::Text { text } => ContentPart::from_text(text.as_str()),
        ContentPartDto::Image {
            content_type,
            base64,
            name,
        }
        | ContentPartDto::File {
            content_type,
            base64,
            name,
        } => ContentPart::from_binary_base64(
            content_type.as_str(),
            base64.as_str(),
            name.clone(),
        ),
    })
}

fn to_chat_message(dto: &ChatMessageDto) -> Result<ChatMessage, ApiError> {
    let content: MessageContent = if let Some(ref parts) = dto.content_parts {
        if parts.is_empty() {
            return Err(ApiError::InvalidRequest(
                "content_parts must not be empty".into(),
            ));
        }
        let genai_parts: Vec<ContentPart> = parts
            .iter()
            .map(content_part_dto_to_genai)
            .collect::<Result<Vec<_>, _>>()?;
        MessageContent::from_parts(genai_parts)
    } else {
        let text = dto
            .content
            .as_deref()
            .unwrap_or("")
            .to_string();
        MessageContent::from_text(text)
    };

    match dto.role.as_str() {
        "system" => Ok(ChatMessage::system(content)),
        "user" => Ok(ChatMessage::user(content)),
        "assistant" => Ok(ChatMessage::assistant(content)),
        _ => Err(ApiError::InvalidRequest(format!(
            "Invalid role: {}",
            dto.role
        ))),
    }
}

/// POST /chat-stream — stream chat completion. Requires auth.
pub async fn chat_stream_handler(
    State(state): State<AppState>,
    _auth: RequireAuth,
    Json(req): Json<ChatStreamRequest>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, ApiError>> + Send + 'static>, ApiError>
{
    if req.model.is_empty() {
        return Err(ApiError::InvalidRequest("model is required".into()));
    }
    if req.messages.is_empty() {
        return Err(ApiError::InvalidRequest("messages is required".into()));
    }

    let messages: Vec<ChatMessage> = req
        .messages
        .iter()
        .map(to_chat_message)
        .collect::<Result<Vec<_>, _>>()?;

    let stream = state
        .ai_service
        .chat_stream(&req.model, messages)
        .await
        .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{:?}", e)))?;

    let sse_stream = stream.map(|result| {
        result
            .map(|s| Event::default().data(s))
            .map_err(|e| ApiError::InternalError(anyhow::anyhow!("{:?}", e)))
    });

    Ok(Sse::new(sse_stream).keep_alive(KeepAlive::default()))
}

pub fn router(_state: &AppState) -> Router<AppState> {
    Router::new().route("/chat-stream", post(chat_stream_handler))
}
