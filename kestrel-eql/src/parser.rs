//! EQL Parser using Pest

use crate::ast::*;
use crate::error::{EqlError, Result};
use pest_derive::Parser;
use pest::Parser;

#[derive(Parser)]
#[grammar = "eql.pest"]
struct EqlParser;

/// Parse EQL query string into AST
pub fn parse(input: &str) -> Result<Query> {
    let pairs = EqlParser::parse(Rule::query, input)
        .map_err(|e| EqlError::syntax("input", &format!("{}", e)))?;

    let mut pairs_iter = pairs;
    let pair = pairs_iter.next().ok_or_else(|| {
        EqlError::syntax("root", "Expected query")
    })?;

    match pair.as_rule() {
        Rule::query => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::event_query => Ok(build_event_query(inner)?),
                Rule::sequence_query => Ok(build_sequence_query(inner)?),
                _ => Err(EqlError::syntax(
                    inner.as_span().as_str(),
                    "Expected event or sequence query",
                )),
            }
        }
        _ => Err(EqlError::syntax(
            pair.as_span().as_str(),
            "Expected query",
        )),
    }
}

fn build_event_query(pair: pest::iterators::Pair<Rule>) -> Result<Query> {
    let mut inner = pair.into_inner();
    let event_type = inner.next().unwrap().as_str().to_string();

    // Check for where clause
    let condition = if let Some(where_pair) = inner.next() {
        Some(build_expr_from_where(where_pair)?)
    } else {
        None
    };

    Ok(Query::Event(Box::new(EventQuery {
        event_type,
        condition,
        captures: Vec::new(),
    })))
}

fn build_sequence_query(pair: pest::iterators::Pair<Rule>) -> Result<Query> {
    let mut inner = pair.into_inner();

    // Skip "sequence" keyword
    inner.next();

    // Parse "by" clause
    inner.next(); // Skip "by"
    let by_field = inner.next().unwrap();
    let by = Some(by_field.as_str().to_string());

    // Parse sequence steps
    let mut steps = Vec::new();
    let mut maxspan = None;
    let mut until = None;

    while let Some(pair) = inner.next() {
        match pair.as_rule() {
            Rule::sequence_step => {
                steps.push(build_sequence_step(pair)?);
            }
            Rule::maxspan_clause => {
                let mut maxspan_inner = pair.into_inner();
                // Skip "with", "maxspan", "="
                maxspan_inner.next();
                maxspan_inner.next();
                maxspan_inner.next();
                if let Some(duration_pair) = maxspan_inner.next() {
                    maxspan = Some(build_duration(duration_pair)?);
                }
            }
            Rule::until_clause => {
                let mut until_inner = pair.into_inner();
                // Skip "until"
                until_inner.next();
                if let Some(until_step) = until_inner.next() {
                    until = Some(Box::new(build_sequence_step(until_step)?));
                }
            }
            _ => {}
        }
    }

    Ok(Query::Sequence(Box::new(SequenceQuery {
        steps,
        by,
        maxspan,
        until,
        captures: Vec::new(),
    })))
}

fn build_sequence_step(pair: pest::iterators::Pair<Rule>) -> Result<SequenceStep> {
    let mut inner = pair.into_inner();

    // Skip "["
    inner.next();

    let event_type = inner.next().unwrap().as_str().to_string();

    // Check for where clause
    let condition = if let Some(where_pair) = inner.next() {
        Some(build_expr_from_where(where_pair)?)
    } else {
        None
    };

    Ok(SequenceStep {
        event_type,
        condition,
        id: None,
    })
}

fn build_expr_from_where(pair: pest::iterators::Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();
    // Skip "where"
    inner.next();
    let expr_pair = inner.next().unwrap();
    build_expr(expr_pair)
}

fn build_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr> {
    let span = pair.as_span().as_str();
    let mut inner = pair.into_inner().next().ok_or_else(|| {
        EqlError::syntax(span, "Expected expression")
    })?;

    match inner.as_rule() {
        Rule::or_expr => build_binary_op(inner),
        Rule::and_expr => build_binary_op(inner),
        Rule::not_expr => build_unary_op(inner),
        Rule::comparison_expr => build_binary_op(inner),
        Rule::primary => build_primary_expr(inner),
        Rule::atom => build_primary_expr(inner),
        Rule::function_call => build_function_call(inner),
        Rule::in_expr_atom => build_in_expr(inner),
        _ => Err(EqlError::syntax(
            inner.as_span().as_str(),
            &format!("Unexpected rule: {:?}", inner.as_rule()),
        )),
    }
}

fn build_primary_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr> {
    let outer_span = pair.as_span().as_str();
    let mut inner = pair.into_inner().next().ok_or_else(|| {
        EqlError::syntax(outer_span, "Expected primary expression")
    })?;

    let span = inner.as_span().as_str();

    match inner.as_rule() {
        Rule::bool_literal => {
            let value = span.parse::<bool>().unwrap();
            Ok(Expr::BoolLiteral(value))
        }
        Rule::int_literal => {
            let value = span.parse::<i64>().unwrap();
            Ok(Expr::IntLiteral(value))
        }
        Rule::string_literal => {
            // Remove quotes
            let unescaped = &span[1..span.len()-1];
            Ok(Expr::StringLiteral(unescaped.to_string()))
        }
        Rule::field_ref => {
            Ok(Expr::FieldRef(span.to_string()))
        }
        Rule::function_call => {
            build_function_call(inner)
        }
        Rule::in_expr_atom => {
            build_in_expr(inner)
        }
        Rule::atom => build_primary_expr(inner),
        Rule::expr => {
            build_expr(inner)
        }
        Rule::comparison_expr => build_binary_op(inner),
        Rule::not_expr => build_unary_op(inner),
        Rule::and_expr => build_binary_op(inner),
        Rule::or_expr => build_binary_op(inner),
        _ => {
            // Check for "null" string
            if span == "null" {
                return Ok(Expr::Null);
            }
            Err(EqlError::syntax(
                span,
                &format!("Unexpected primary expression: {:?}", inner.as_rule()),
            ))
        }
    }
}

fn build_function_call(pair: pest::iterators::Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();
    let function = inner.next().unwrap().as_str().to_string();

    let mut args = Vec::new();

    if let Some(expr_list_pair) = inner.next() {
        for arg_pair in expr_list_pair.into_inner() {
            args.push(build_expr(arg_pair)?);
        }
    }

    Ok(Expr::FunctionCall(FunctionCall { function, args }))
}

fn build_in_expr(pair: pest::iterators::Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();

    let value = Box::new(build_expr(inner.next().unwrap())?);

    let mut values = Vec::new();

    // Skip "in", "(", and parse expr_list
    inner.next(); // skip "in"
    inner.next(); // skip "("

    if let Some(expr_list_pair) = inner.next() {
        for val_pair in expr_list_pair.into_inner() {
            values.push(build_expr(val_pair)?);
        }
    }

    Ok(Expr::In(Box::new(InExpr { value, values })))
}

fn build_binary_op(pair: pest::iterators::Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();
    let first = build_expr(inner.next().unwrap())?;

    let mut result = first;

    while let Some(op_pair) = inner.next() {
        let operator = parse_operator_from_str(op_pair.as_span().as_str())?;
        let right = build_expr(inner.next().unwrap())?;

        result = Expr::BinaryOp(Box::new(BinaryOp {
            operator,
            left: result,
            right,
        }));
    }

    Ok(result)
}

fn parse_operator_from_str(s: &str) -> Result<BinaryOperator> {
    match s {
        "and" | "&&" => Ok(BinaryOperator::And),
        "or" | "||" => Ok(BinaryOperator::Or),
        "==" => Ok(BinaryOperator::Eq),
        "!=" => Ok(BinaryOperator::NotEq),
        "<" => Ok(BinaryOperator::Less),
        "<=" => Ok(BinaryOperator::LessEq),
        ">" => Ok(BinaryOperator::Greater),
        ">=" => Ok(BinaryOperator::GreaterEq),
        "+" => Ok(BinaryOperator::Add),
        "-" => Ok(BinaryOperator::Sub),
        "*" => Ok(BinaryOperator::Mul),
        "/" => Ok(BinaryOperator::Div),
        "%" => Ok(BinaryOperator::Mod),
        _ => Err(EqlError::syntax(s, "Unknown operator")),
    }
}

fn build_unary_op(pair: pest::iterators::Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();

    // Check if this is a not operation
    let first = inner.next();
    if first.as_ref().is_some() && first.as_ref().unwrap().as_rule() == Rule::not_op {
        let operand = build_expr(inner.next().unwrap())?;
        Ok(Expr::UnaryOp(Box::new(UnaryOp {
            operator: UnaryOperator::Not,
            operand,
        })))
    } else {
        // Just a regular expression
        if let Some(p) = first {
            build_expr(p)
        } else {
            Err(EqlError::syntax("unary", "Expected expression"))
        }
    }
}

fn build_duration(pair: pest::iterators::Pair<Rule>) -> Result<Duration> {
    let text = pair.as_str();

    // Extract numeric value
    let mut char_iter = text.chars();
    let mut value_str = String::new();

    for c in char_iter.by_ref() {
        if c.is_ascii_digit() {
            value_str.push(c);
        } else {
            break;
        }
    }

    let value: u64 = value_str.parse().map_err(|_| {
        EqlError::syntax(text, "Invalid duration value")
    })?;

    let remaining: String = char_iter.collect();
    let unit = match remaining.as_str() {
        "ms" => DurationUnit::Milliseconds,
        "s" => DurationUnit::Seconds,
        "m" => DurationUnit::Minutes,
        "h" => DurationUnit::Hours,
        _ => return Err(EqlError::syntax(text, "Invalid duration unit")),
    };

    Ok(Duration { value, unit })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_event() {
        let result = parse("process where process.executable == \"/bin/bash\"").unwrap();
        match result {
            Query::Event(eq) => {
                assert_eq!(eq.event_type, "process");
                assert!(eq.condition.is_some());
            }
            _ => panic!("Expected event query"),
        }
    }

    #[test]
    fn test_parse_sequence() {
        let result = parse("sequence by process.entity_id [process] [file]").unwrap();
        match result {
            Query::Sequence(sq) => {
                assert_eq!(sq.steps.len(), 2);
            }
            _ => panic!("Expected sequence query"),
        }
    }
}
