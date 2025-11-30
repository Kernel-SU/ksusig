//! Digesting functions for Module
//!
//! This module re-exports digest functions from file_formats::module::digest
//! for backward compatibility.
//!
//! Gated behind the `hash` feature

#![cfg(feature = "hash")]

// Re-export all digest functions from the new location
pub use crate::file_formats::module::digest::*;
