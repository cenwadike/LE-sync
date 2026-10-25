//! Predicate evaluation over a verified value (`no_std`, no alloc). PROVISIONAL.
//!
//! A predicate names one 32-byte word of what a proof has verified, an operator and an
//! operand. The word comes from the verified data only (`Subject`); the operand comes from
//! the caller. Operators: equality and inequality (the RFP minimum).
//!
//! Fail closed: a predicate that does not hold returns `Error::PredicateFalse` (206), so a
//! statement is emitted only for a predicate that is true. So does a predicate whose target
//! is not in the subject (a topic the log lacks, a data word past the end of the data, a
//! storage target applied to a log). A missing value never satisfies `Ne`.
//!
//! Provisional: whether a false predicate is an error or a reported result, and the set of
//! operators, are fixed by RFP-021 Func #4. Both are confined to this file.

use crate::receipt::Log;
use crate::{Bytes32, Error};

/// Which word of the subject the predicate reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Account balance, big-endian word.
    Balance,
    /// Storage slot value, big-endian word.
    StorageValue,
    /// Log topic `i` (0 is the event signature for non-anonymous events).
    Topic(usize),
    /// The `i`-th 32-byte word of the log data.
    DataWord(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Predicate {
    pub target: Target,
    pub op: Op,
    pub operand: Bytes32,
}

/// What a proof verified: the only values a predicate may read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject<'a> {
    Account { balance: Bytes32 },
    Storage { value: Bytes32 },
    Log(Log<'a>),
}

fn word_of(target: Target, subject: &Subject<'_>) -> Option<Bytes32> {
    match (target, subject) {
        (Target::Balance, Subject::Account { balance }) => Some(*balance),
        (Target::StorageValue, Subject::Storage { value }) => Some(*value),
        (Target::Topic(i), Subject::Log(log)) => {
            if i < log.topic_count {
                log.topics.get(i).copied()
            } else {
                None
            }
        }
        (Target::DataWord(i), Subject::Log(log)) => {
            let start = i.checked_mul(32)?;
            let mut w = [0u8; 32];
            w.copy_from_slice(log.data.get(start..)?.get(..32)?);
            Some(w)
        }
        _ => None,
    }
}

impl Predicate {
    /// `Ok(())` if the predicate holds over `subject`; `Err(PredicateFalse)` otherwise.
    pub fn evaluate(&self, subject: &Subject<'_>) -> Result<(), Error> {
        let word = word_of(self.target, subject).ok_or(Error::PredicateFalse)?;
        let equal = word == self.operand;
        let holds = match self.op {
            Op::Eq => equal,
            Op::Ne => !equal,
        };
        if holds {
            Ok(())
        } else {
            Err(Error::PredicateFalse)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(n: u8) -> Bytes32 {
        [n; 32]
    }
    fn log() -> Log<'static> {
        // two topics, 40 bytes of data: one whole word then 8 stray bytes
        static DATA: [u8; 40] = [0x33; 40];
        Log {
            address: [0xA1; 20],
            topics: [w(1), w(2), [0; 32], [0; 32]],
            topic_count: 2,
            data: &DATA,
        }
    }
    fn p(target: Target, op: Op, operand: Bytes32) -> Predicate {
        Predicate {
            target,
            op,
            operand,
        }
    }
    fn subjects() -> Vec<(Target, Subject<'static>, Bytes32)> {
        vec![
            (Target::Balance, Subject::Account { balance: w(5) }, w(5)),
            (Target::StorageValue, Subject::Storage { value: w(6) }, w(6)),
            (Target::Topic(0), Subject::Log(log()), w(1)),
            (Target::Topic(1), Subject::Log(log()), w(2)),
            (Target::DataWord(0), Subject::Log(log()), w(0x33)),
        ]
    }

    #[test]
    fn eq_and_ne_each_pass_and_fail_for_every_target() {
        for (t, s, actual) in subjects() {
            let other = w(0xEE);
            assert_ne!(actual, other);
            // Eq: passes on the actual word, fails on another
            assert_eq!(p(t, Op::Eq, actual).evaluate(&s), Ok(()), "{t:?} eq pass");
            assert_eq!(
                p(t, Op::Eq, other).evaluate(&s),
                Err(Error::PredicateFalse),
                "{t:?} eq fail"
            );
            // Ne: passes on another word, fails on the actual one
            assert_eq!(p(t, Op::Ne, other).evaluate(&s), Ok(()), "{t:?} ne pass");
            assert_eq!(
                p(t, Op::Ne, actual).evaluate(&s),
                Err(Error::PredicateFalse),
                "{t:?} ne fail"
            );
        }
    }

    #[test]
    fn one_changed_byte_in_the_operand_flips_the_result() {
        let s = Subject::Account { balance: w(5) };
        let mut o = w(5);
        assert_eq!(p(Target::Balance, Op::Eq, o).evaluate(&s), Ok(()));
        for i in 0..32 {
            o[i] ^= 1;
            assert_eq!(
                p(Target::Balance, Op::Eq, o).evaluate(&s),
                Err(Error::PredicateFalse),
                "byte {i}"
            );
            assert_eq!(p(Target::Balance, Op::Ne, o).evaluate(&s), Ok(()));
            o[i] ^= 1;
        }
    }

    #[test]
    fn zero_is_a_value_like_any_other() {
        let s = Subject::Storage { value: [0; 32] };
        assert_eq!(
            p(Target::StorageValue, Op::Eq, [0; 32]).evaluate(&s),
            Ok(())
        );
        assert_eq!(
            p(Target::StorageValue, Op::Ne, [0; 32]).evaluate(&s),
            Err(Error::PredicateFalse)
        );
    }

    #[test]
    fn a_target_missing_from_the_subject_never_passes_either_operator() {
        let l = Subject::Log(log());
        let acct = Subject::Account { balance: w(5) };
        let stor = Subject::Storage { value: w(6) };
        let missing = [
            (Target::Topic(2), l), // log has 2 topics
            (Target::Topic(3), l), // within the 4-topic maximum, but absent
            (Target::Topic(4), l), // beyond any log
            (Target::Topic(usize::MAX), l),
            (Target::DataWord(1), l), // 40 bytes: word 1 would need 64
            (Target::DataWord(usize::MAX), l),
            (Target::DataWord(usize::MAX / 32 + 1), l), // i * 32 overflows
            (Target::Balance, l),
            (Target::StorageValue, l),
            (Target::Topic(0), acct),
            (Target::DataWord(0), stor),
            (Target::Balance, stor),
            (Target::StorageValue, acct),
        ];
        // operands include zero, which a missing word must not be mistaken for
        for (t, s) in missing {
            for operand in [[0u8; 32], w(1), w(0x33)] {
                for op in [Op::Eq, Op::Ne] {
                    assert_eq!(
                        p(t, op, operand).evaluate(&s),
                        Err(Error::PredicateFalse),
                        "{t:?} {op:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn data_words_are_whole_and_exact() {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&w(0x11));
        data[32..].copy_from_slice(&w(0x22));
        let l = Subject::Log(Log {
            address: [0; 20],
            topics: [[0; 32]; 4],
            topic_count: 0,
            data: &data,
        });
        assert_eq!(p(Target::DataWord(0), Op::Eq, w(0x11)).evaluate(&l), Ok(()));
        assert_eq!(p(Target::DataWord(1), Op::Eq, w(0x22)).evaluate(&l), Ok(()));
        assert_eq!(
            p(Target::DataWord(2), Op::Ne, w(0x22)).evaluate(&l),
            Err(Error::PredicateFalse)
        );
        // the last data byte matters
        let mut o = w(0x22);
        o[31] ^= 1;
        assert_eq!(
            p(Target::DataWord(1), Op::Eq, o).evaluate(&l),
            Err(Error::PredicateFalse)
        );
        // exactly one word of data: word 0 only
        let one = Subject::Log(Log {
            address: [0; 20],
            topics: [[0; 32]; 4],
            topic_count: 0,
            data: &data[..32],
        });
        assert_eq!(
            p(Target::DataWord(0), Op::Eq, w(0x11)).evaluate(&one),
            Ok(())
        );
        assert_eq!(
            p(Target::DataWord(1), Op::Eq, w(0x22)).evaluate(&one),
            Err(Error::PredicateFalse)
        );
    }
}
