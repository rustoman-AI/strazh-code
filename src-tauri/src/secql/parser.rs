use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_till1, take_while1},
    character::complete::{alpha1, alphanumeric1, char, digit1, multispace0, multispace1},
    combinator::{map, map_res, opt, recognize},
    multi::{many0, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

use super::ast::*;

// ─────────────────────────────────────────────────────────
//  Basic Tokens & Helpers
// ─────────────────────────────────────────────────────────

fn sp(i: &str) -> IResult<&str, &str> {
    multispace0(i)
}

fn sp1(i: &str) -> IResult<&str, &str> {
    multispace1(i)
}

fn identifier(i: &str) -> IResult<&str, &str> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0(alt((alphanumeric1, tag("_"), tag("-")))),
    ))(i)
}

fn parse_string_literal(i: &str) -> IResult<&str, String> {
    let parse_single = delimited(char('\''), take_till1(|c| c == '\''), char('\''));
    let parse_double = delimited(char('"'), take_till1(|c| c == '"'), char('"'));
    map(alt((parse_single, parse_double)), |s: &str| s.to_string())(i)
}

fn parse_number_literal(i: &str) -> IResult<&str, f64> {
    map_res(
        recognize(tuple((
            opt(char('-')),
            digit1,
            opt(tuple((char('.'), digit1))),
        ))),
        |s: &str| s.parse::<f64>(),
    )(i)
}

fn parse_boolean_literal(i: &str) -> IResult<&str, bool> {
    alt((
        map(tag_no_case("true"), |_| true),
        map(tag_no_case("false"), |_| false),
    ))(i)
}

fn parse_filter_value(i: &str) -> IResult<&str, FilterValue> {
    alt((
        map(parse_string_literal, FilterValue::String),
        map(parse_boolean_literal, FilterValue::Boolean),
        map(parse_number_literal, FilterValue::Number),
    ))(i)
}

fn parse_operator(i: &str) -> IResult<&str, ComparisonOp> {
    alt((
        map(tag("="), |_| ComparisonOp::Eq),
        map(tag("!="), |_| ComparisonOp::NotEq),
        map(tag(">"), |_| ComparisonOp::Gt),
        map(tag("<"), |_| ComparisonOp::Lt),
        map(tag_no_case("CONTAINS"), |_| ComparisonOp::Contains),
    ))(i)
}

// ─────────────────────────────────────────────────────────
//  Properties: { key: "value", age > 10 }
// ─────────────────────────────────────────────────────────

fn parse_property_filter(i: &str) -> IResult<&str, PropertyFilter> {
    let (i, key) = preceded(sp, identifier)(i)?;
    
    // Support Cypher shorthand `{key: "val"}` as `key = "val"`
    let (i, op) = preceded(sp, alt((parse_operator, map(tag(":"), |_| ComparisonOp::Eq))))(i)?;
    
    let (i, value) = preceded(sp, parse_filter_value)(i)?;
    
    Ok((i, PropertyFilter {
        key: key.to_string(),
        operator: op,
        value,
    }))
}

fn parse_properties(i: &str) -> IResult<&str, Vec<PropertyFilter>> {
    delimited(
        preceded(sp, char('{')),
        separated_list1(preceded(sp, char(',')), parse_property_filter),
        preceded(sp, char('}')),
    )(i)
}

// ─────────────────────────────────────────────────────────
//  Nodes: (n), (api:EntryPoint), (comp:Component {license: "GPL"})
// ─────────────────────────────────────────────────────────

fn parse_node(i: &str) -> IResult<&str, MatchElement> {
    let (i, _) = preceded(sp, char('('))(i)?;
    
    let (i, binding) = opt(preceded(sp, identifier))(i)?;
    
    let (i, node_type) = opt(preceded(
        preceded(sp, char(':')), 
        preceded(sp, identifier)
    ))(i)?;
    
    let (i, properties) = opt(parse_properties)(i)?;
    
    let (i, _) = preceded(sp, char(')'))(i)?;

    Ok((i, MatchElement::Node(NodePattern {
        binding: binding.map(|s| s.to_string()),
        node_type: node_type.map(|s| s.to_string()),
        properties: properties.unwrap_or_default(),
    })))
}

// ─────────────────────────────────────────────────────────
//  Edges: -[r]->, -[:CALLS*1..5]->
// ─────────────────────────────────────────────────────────

fn parse_hop_range(i: &str) -> IResult<&str, (usize, Option<usize>)> {
    let (i, _) = preceded(sp, char('*'))(i)?;
    let (i, min_str) = opt(digit1)(i)?;
    
    let (i, has_dots) = opt(tag(".."))(i)?;
    
    let (i, max_str) = if has_dots.is_some() {
        opt(digit1)(i)?
    } else {
        (i, None)
    };

    let min = min_str.and_then(|s| s.parse::<usize>().ok()).unwrap_or(1);
    
    let max = if has_dots.is_some() {
        max_str.and_then(|s: &str| s.parse::<usize>().ok())
    } else {
        Some(min) // exact matching like *3
    };

    Ok((i, (min, max)))
}

fn parse_edge(i: &str) -> IResult<&str, MatchElement> {
    // -[
    let (i, _) = preceded(sp, tag("-["))(i)?;
    
    let (i, parts) = opt(pair(
        opt(delimited(sp, identifier, preceded(sp, char(':')))),
        preceded(sp, identifier)
    ))(i)?;

    let (binding, edge_type) = match parts {
        Some((Some(b), e)) => (Some(b.to_string()), Some(e.to_string())),
        Some((None, e)) => (None, Some(e.to_string())),
        None => (None, None),
    };

    let (i, hop_range) = opt(parse_hop_range)(i)?;
    
    let (i, properties) = opt(parse_properties)(i)?;
    
    // ]->
    let (i, _) = preceded(sp, tag("]->"))(i)?;

    Ok((i, MatchElement::Edge(EdgePattern {
        binding: binding.map(|s| s.to_string()),
        edge_type: edge_type.map(|s| s.to_string()),
        hop_range,
        properties: properties.unwrap_or_default(),
    })))
}

// ─────────────────────────────────────────────────────────
//  Clauses: MATCH ... RETURN ...
// ─────────────────────────────────────────────────────────

fn parse_match_elements(i: &str) -> IResult<&str, Vec<MatchElement>> {
    let mut i = i;
    let mut elements = Vec::new();
    
    // Start with a node
    let (next_i, node) = parse_node(i)?;
    elements.push(node);
    i = next_i;
    
    // Followed by 0 or more (Edge -> Node) pairs
    while let Ok((next_i, edge)) = parse_edge(i) {
        if let Ok((final_i, node)) = parse_node(next_i) {
            elements.push(edge);
            elements.push(node);
            i = final_i;
        } else {
            break;
        }
    }
    
    Ok((i, elements))
}

fn parse_match_clause(i: &str) -> IResult<&str, MatchClause> {
    let (i, _) = preceded(sp, tag_no_case("MATCH"))(i)?;
    let (i, elements) = parse_match_elements(i)?;
    Ok((i, MatchClause { elements }))
}

fn parse_return_clause(i: &str) -> IResult<&str, ReturnClause> {
    let (i, _) = preceded(sp, tag_no_case("RETURN"))(i)?;
    let (i, targets) = separated_list1(
        preceded(sp, char(',')),
        preceded(sp, take_while1(|c: char| c.is_alphanumeric() || c == '.' || c == '_')),
    )(i)?;
    
    Ok((i, ReturnClause {
        targets: targets.iter().map(|s| s.to_string()).collect()
    }))
}

pub fn parse_secql(i: &str) -> IResult<&str, Query> {
    let (i, m) = parse_match_clause(i)?;
    let (i, ret) = parse_return_clause(i)?;
    let (i, _) = sp(i)?; // consume trailing spaces
    Ok((i, Query {
        matches: vec![m],
        ret,
    }))
}

// ─────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_node() {
        let q = "MATCH (n) RETURN n";
        let (_, query) = parse_secql(q).unwrap();
        assert_eq!(query.matches[0].elements.len(), 1);
        assert_eq!(query.ret.targets[0], "n");
        if let MatchElement::Node(n) = &query.matches[0].elements[0] {
            assert_eq!(n.binding.as_deref(), Some("n"));
            assert_eq!(n.node_type, None);
        } else {
            panic!("Expected node");
        }
    }

    #[test]
    fn test_parse_darpa_query() {
        let q = r#"
            MATCH (api:EntryPoint {protocol: "http"})
            -[CALLS*1..5]-> (func:ASTNode)
            -[USES]-> (comp:Component {license: "GPL-3.0"})
            RETURN path
        "#;
        let (_, query) = parse_secql(q).unwrap();
        
        assert_eq!(query.matches[0].elements.len(), 5); // N -> E -> N -> E -> N
        assert_eq!(query.ret.targets[0], "path");

        // Edge 1 (Index 1)
        if let MatchElement::Edge(e) = &query.matches[0].elements[1] {
            assert_eq!(e.edge_type.as_deref(), Some("CALLS"));
            assert_eq!(e.hop_range, Some((1, Some(5))));
        } else {
            panic!("Expected edge");
        }
        
        // Node 3 (Index 4)
        if let MatchElement::Node(n) = &query.matches[0].elements[4] {
            assert_eq!(n.binding.as_deref(), Some("comp"));
            assert_eq!(n.node_type.as_deref(), Some("Component"));
            assert_eq!(n.properties.len(), 1);
            assert_eq!(n.properties[0].key, "license");
            assert!(matches!(n.properties[0].operator, ComparisonOp::Eq));
        } else {
            panic!("Expected node");
        }
    }
}
