//! Recording traffic: streaming body capture, the event store, redaction, and reading captures back.

pub mod read;
pub mod redact;
pub mod store;
pub mod tee;

pub use store::Store;
pub use tee::{boxed, empty, full, tee, BoxError, Captured, ProxyBody};
