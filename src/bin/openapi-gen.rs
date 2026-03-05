//! Writes the OpenAPI spec to openapi.json for static use or CI.
//! Run with: cargo run --bin openapi-gen

fn main() {
    let spec = server::openapi_spec();
    let json = serde_json::to_string_pretty(&spec).expect("serialize OpenAPI");
    let path = std::path::Path::new("openapi.json");
    std::fs::write(path, json).expect("write openapi.json");
    println!("Generated {}", path.display());
}
