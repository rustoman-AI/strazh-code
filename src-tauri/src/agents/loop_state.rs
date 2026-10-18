use serde::{Deserialize, Serialize};

/// The 10-stage execution state of an AI Agent in the ZeroClaw loop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentState {
    /// Step 1: Initialize, check preconditions, or setup.
    PreHook,
    /// Step 2: Gather memory, DAG inputs, and environmental facts.
    ContextAssembly,
    /// Step 3: Construct the final LLM prompt.
    BuildPrompt,
    /// Step 4 & 8: Interacting with the external LLM provider API.
    LLMProvider,
    /// Step 5: Parsing the raw textual output from the LLM.
    ParseResponse,
    /// Step 6: Triggering a Tool Call based on parsed output.
    ExecuteTool,
    /// Step 7: Tool call finished, injecting result back into context.
    ProvideToolResult,
    /// Step 9: Final answer text generation completed.
    FinalAnswer,
    /// Step 10: Cleanup, logging, or moving to the next DAG node.
    PostHook,
}

impl AgentState {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentState::PreHook => "PreHook",
            AgentState::ContextAssembly => "ContextAssembly",
            AgentState::BuildPrompt => "BuildPrompt",
            AgentState::LLMProvider => "LLMProvider",
            AgentState::ParseResponse => "ParseResponse",
            AgentState::ExecuteTool => "ExecuteTool",
            AgentState::ProvideToolResult => "ProvideToolResult",
            AgentState::FinalAnswer => "FinalAnswer",
            AgentState::PostHook => "PostHook",
        }
    }
}
