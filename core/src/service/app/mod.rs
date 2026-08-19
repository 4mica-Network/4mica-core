//! Application entrypoints: the composition root, the chain event handler, and the scheduled
//! tasks. These may depend on any domain service; nothing depends on them.

pub mod core;
pub mod events;
pub mod tasks;
