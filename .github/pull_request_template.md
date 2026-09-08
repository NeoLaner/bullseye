## What and why


## Knowledge Impact

Per `knowledge/` — a behaviour change merges only with its knowledge, contract
and tests. Tick what moved, or record the reason nothing did.

- [ ] No knowledge change — reason recorded
- [ ] Feature Spec changed
- [ ] Business Rule changed
- [ ] New or superseding ADR/PDR needed
- [ ] API/Event/Device contract changed
- [ ] Acceptance scenario changed
- [ ] Runbook or monitoring changed
- [ ] Release note changed
- [ ] Research note added or re-verified

## Lockout check

A kill switch bug takes a machine offline with no obvious cause. For any change
touching rule generation:

- [ ] `cargo test` passes — `tests/lockout_guards.rs` is this checklist, executed:
      empty upstream refused, tunnel required, `/0` holes refused, unparsed input
      rejected, escape hatch present in `--help`
- [ ] `bullseye arm --dry-run` renders and validates against the kernel (needs root,
      so it is not in `cargo test` — run it by hand when rule generation changed)
