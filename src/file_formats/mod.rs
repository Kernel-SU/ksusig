//! File format implementations
//!
//! This module provides support for different file formats that can be signed.

pub mod module;

#[cfg(feature = "elf")]
pub mod elf;
