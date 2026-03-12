//! AI chat service wrapping genai Client for streaming completions.

use futures_util::stream::Stream;
use futures_util::StreamExt;
use genai::chat::{ChatMessage, ChatRequest, ChatStreamEvent};
use genai::Client;
use std::pin::Pin;

type ChatStream = Pin<Box<dyn Stream<Item = Result<String, genai::Error>> + Send + 'static>>;

/// Service for chat completions via genai (Ollama, OpenAI, Anthropic, Gemini, etc.).
#[derive(Clone)]
pub struct AiService {
    client: Client,
}

impl AiService {
    pub fn new() -> Self {
        Self {
            client: Client::default(),
        }
    }

    /// Stream chat response text chunks. Maps genai ChatStreamEvent to String chunks.
    pub async fn chat_stream(
        &self,
        model: &str,
        messages: Vec<ChatMessage>,
    ) -> Result<ChatStream, genai::Error> {
        let request = ChatRequest::new(messages);
        let chat_res = self
            .client
            .exec_chat_stream(model, request, None)
            .await?;

        let stream = chat_res.stream.filter_map(|event| {
            let result = match event {
                Ok(ChatStreamEvent::Chunk(chunk))
                | Ok(ChatStreamEvent::ReasoningChunk(chunk))
                | Ok(ChatStreamEvent::ThoughtSignatureChunk(chunk)) => {
                    if chunk.content.is_empty() {
                        None
                    } else {
                        Some(Ok(chunk.content))
                    }
                }
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            };
            std::future::ready(result)
        });

        Ok(Box::pin(stream))
    }
}
