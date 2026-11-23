//! Built-in security analysis rules.

use super::Rule;

/// All built-in security rules, run by `wirelint sast`.
pub static BUILT_INS: &[&dyn Rule] = &[];
