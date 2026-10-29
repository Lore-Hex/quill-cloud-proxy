//! Transport building blocks. Catalog activation remains separately gated.
pub mod relay;

pub const BACKEND: &str = "https://enclave.trymaple.ai";
pub const MODEL: &str = "deepseek-v4-1-flash-1017-uncensored";
// Candidate pin, pending independent image reproduction and release review.
pub const PCR0: &str = "ada74c7aa10cbde75f83d7ec674cc4fc4a4cf9cc555e367189fbec332dffa985c6082ae4647fd50242a590bf9cd1d3f0";
