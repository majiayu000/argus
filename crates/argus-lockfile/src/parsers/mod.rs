use crate::{BoundedInput, DetectedLockfile, LockfileError, LockfileFormat, ParseOutput};

pub mod bundler;
pub mod cargo;
pub mod composer;
pub mod go_sum;
pub mod package_lock;
pub mod pnpm;
pub mod poetry;
pub mod uv;
pub mod yarn;

/// Frozen parser boundary for every format lane.
pub trait LockfileParser: Send + Sync {
    fn format(&self) -> LockfileFormat;

    fn parse(
        &self,
        input: &BoundedInput<'_>,
        detected: &DetectedLockfile,
    ) -> Result<ParseOutput, LockfileError>;
}

pub fn parser_for(format: LockfileFormat) -> &'static dyn LockfileParser {
    match format {
        LockfileFormat::PackageLock => &package_lock::PARSER,
        LockfileFormat::YarnClassic | LockfileFormat::YarnBerry => &yarn::PARSER,
        LockfileFormat::Pnpm => &pnpm::PARSER,
        LockfileFormat::Poetry => &poetry::PARSER,
        LockfileFormat::Uv => &uv::PARSER,
        LockfileFormat::Cargo => &cargo::PARSER,
        LockfileFormat::GoSum => &go_sum::PARSER,
        LockfileFormat::Bundler => &bundler::PARSER,
        LockfileFormat::Composer => &composer::PARSER,
    }
}
