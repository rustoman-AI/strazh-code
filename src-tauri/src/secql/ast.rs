use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Query {
    pub matches: Vec<MatchClause>,
    pub ret: ReturnClause,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchClause {
    pub elements: Vec<MatchElement>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MatchElement {
    Node(NodePattern),
    Edge(EdgePattern),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodePattern {
    pub binding: Option<String>,
    pub node_type: Option<String>,
    pub properties: Vec<PropertyFilter>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EdgePattern {
    pub binding: Option<String>,
    pub edge_type: Option<String>,
    pub hop_range: Option<(usize, Option<usize>)>, // (min, max), e.g. *1..5
    pub properties: Vec<PropertyFilter>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PropertyFilter {
    pub key: String,
    pub operator: ComparisonOp,
    pub value: FilterValue,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComparisonOp {
    Eq,     // =
    NotEq,  // !=
    Gt,     // >
    Lt,     // <
    Contains, // CONTAINS
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FilterValue {
    String(String),
    Number(f64),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReturnClause {
    pub targets: Vec<String>, // e.g. "path", "api", "comp.name"
}
