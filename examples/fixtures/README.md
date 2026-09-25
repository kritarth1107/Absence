# Test Fixtures

This directory contains sample data for testing and examples.

## Files

- `sample_facts.json` - Example facts that might be recorded in a store
- `sample_absence_proof.json` - Example proof format (incomplete, for illustration)
- `batch_absent_facts.jsonl` - JSON lines of facts to prove absent (for `prove-absent-batch --file`)

## Usage

```bash
# Load facts from file
cat examples/fixtures/sample_facts.json | jq -c '.[]' | while read fact; do
  absence insert "$fact"
done

# Batch-prove absences from JSONL
absence prove-absent-batch --file examples/fixtures/batch_absent_facts.jsonl -o batch.json

# Or in Rust
let facts: Vec<serde_json::Value> = serde_json::from_str(include_str!("fixtures/sample_facts.json")).unwrap();
for fact in &facts {
    store.record_json(fact).unwrap();
}
```
