pub mod crypto;
pub mod transaction;
pub mod block;
pub mod storage;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "client")]
pub mod viewer;

#[cfg(feature = "client")]
pub mod pool;

#[cfg(any(feature = "shard", feature = "validator"))]
pub mod security;

#[cfg(feature = "shard")]
pub mod shard;

#[cfg(feature = "validator")]
pub mod validator;

/// Calculate required amount of block approvals for provided amount of
/// blockchain validators at the current moment.
///
/// The rule is `(n - 1) * 2 / 3` for `n > 0`, otherwise it's `0`.
///
/// - For no validators there's no need in approvals.
/// - For one validator - it's the one who signed the block, so no need in
///   approvals.
/// - For two validators - one of them made the block, the other one's opinion
///   is not important enough.
/// - For three validators - one of them made the block, and at least one
///   approval is required.
/// - and so on...
pub fn calc_required_approvals(validators: usize) -> usize {
    if validators == 0 {
        0
    } else {
        (validators - 1) * 2 / 3
    }
}
