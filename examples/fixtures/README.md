# Test Fixtures

This directory contains sample data for testing and examples.

## Files

- `sample_facts.json` - Example facts that might be recorded in a store
- `sample_absence_proof.json` - Example proof format (incomplete, for illustration)

## Usage

```bash
# Load facts from file
cat examples/fixtures/sample_facts.json | jq -c '.[]' | while read fact; do
  absence insert "$fact"
done

# Or in Rust
let facts: Vec<serde_json::Value> = serde_json::from_str(include_str!("fixtures/sample_facts.json")).unwrap();
for fact in &facts {
    store.record_json(fact).unwrap();
}
```
