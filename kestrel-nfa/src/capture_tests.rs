#[cfg(test)]
mod capture_tests {
    use super::*;
    use crate::state::{NfaSequence, PartialMatch, SeqStep};
    use kestrel_eql::ir::IrCapture;
    use kestrel_event::Event;
    use kestrel_schema::{FieldDataType, FieldDef, SchemaRegistry, TypedValue};
    use std::sync::Arc;

    #[test]
    fn test_extract_captures_simple() {
        let mut schema = SchemaRegistry::new();

        let exec_field_id = schema
            .register_field(FieldDef {
                path: "process.executable".to_string(),
                data_type: FieldDataType::String,
                description: None,
            })
            .unwrap();

        let pid_field_id = schema
            .register_field(FieldDef {
                path: "process.pid".to_string(),
                data_type: FieldDataType::U64,
                description: None,
            })
            .unwrap();

        let schema = Arc::new(schema);

        let config = NfaEngineConfig::default();
        let engine = NfaEngine::new(config, std::sync::Arc::new(TestPredicateEvaluator), schema);

        let captures = vec![
            IrCapture {
                field_id: exec_field_id,
                alias: "exe".to_string(),
                source_step: Some("0".to_string()),
            },
            IrCapture {
                field_id: pid_field_id,
                alias: "pid".to_string(),
                source_step: Some("1".to_string()),
            },
        ];

        let sequence = NfaSequence::with_captures(
            "test_seq".to_string(),
            100,
            vec![
                SeqStep::new(0, "pred1".to_string(), 1),
                SeqStep::new(1, "pred2".to_string(), 2),
            ],
            Some(5000),
            None,
            captures,
        );

        let event1 = Event::builder()
            .event_type(1)
            .ts_mono(1000)
            .ts_wall(1000)
            .entity_key(123)
            .field(exec_field_id, TypedValue::String("/bin/bash".into()))
            .build()
            .unwrap();

        let event2 = Event::builder()
            .event_type(2)
            .ts_mono(2000)
            .ts_wall(2000)
            .entity_key(123)
            .field(pid_field_id, TypedValue::U64(1234))
            .build()
            .unwrap();

        let captures = engine
            .extract_captures(&sequence, &[event1.clone(), event2.clone()])
            .unwrap();

        assert_eq!(captures.len(), 2);
        assert_eq!(captures[0].0, "exe");
        assert_eq!(captures[0].1, TypedValue::String("/bin/bash".into()));
        assert_eq!(captures[1].0, "pid");
        assert_eq!(captures[1].1, TypedValue::U64(1234));
    }

    struct TestPredicateEvaluator;

    impl crate::PredicateEvaluator for TestPredicateEvaluator {
        fn evaluate(&self, _predicate_id: &str, _event: &Event) -> NfaResult<bool> {
            Ok(true)
        }

        fn get_required_fields(&self, _predicate_id: &str) -> NfaResult<Vec<u32>> {
            Ok(vec![])
        }

        fn has_predicate(&self, _predicate_id: &str) -> bool {
            true
        }
    }
}
