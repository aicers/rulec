//! A rule compiler for public signature rules.
//!
//! `rulec` unpacks the ET Open and SigmaHQ rule sets, converts them into
//! one Sigma-based rule format, compiles them with vectorscan and matches
//! them against the raw event types of `giganto-client`. This release is
//! the crate's skeleton: it carries those dependencies and no rule
//! handling yet.

// Nothing outside the tests calls into these crates yet; the skeleton
// carries them so the build proves they compile and link. Naming them
// here keeps rustc's `unused_crate_dependencies` lint, and tools that
// flag unused dependencies, quiet until the code that uses them lands.
use giganto_client as _;
use vectorscan_rs as _;

#[cfg(test)]
mod tests {
    use vectorscan_rs::{BlockDatabase, Flag, Pattern, Scan};

    /// Compiles one pattern with vectorscan and scans one input with it,
    /// which fails to build or run unless vectorscan is linked.
    #[test]
    fn vectorscan_compiles_and_scans() {
        const PATTERN_ID: u32 = 7;

        let pattern = Pattern::new(b"rule[0-9]+c".to_vec(), Flag::empty(), Some(PATTERN_ID));
        let db = BlockDatabase::new(vec![pattern]).expect("compile the pattern");
        let mut scanner = db.create_scanner().expect("allocate scratch space");

        let mut matches = Vec::new();
        scanner
            .scan(b"a rule42c match", |id, _from, to, _flags| {
                matches.push((id, to));
                Scan::Continue
            })
            .expect("scan the input");
        assert_eq!(matches, vec![(PATTERN_ID, 9)]);

        let mut misses = 0_usize;
        scanner
            .scan(b"no hit here", |_, _, _, _| {
                misses += 1;
                Scan::Continue
            })
            .expect("scan the input");
        assert_eq!(misses, 0);
    }
}
