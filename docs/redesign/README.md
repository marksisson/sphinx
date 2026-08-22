# CLI redesign implementation records

The implementation is governed by [`REDESIGN.md`](../../REDESIGN.md).

Phase 0 freezes:

- [accepted architecture decisions](../adr/README.md);
- [canonical terminology](TERMINOLOGY.md);
- [the initial command matrix](COMMAND_MATRIX.md); and
- [executable fixtures](../../testdata/phase0/README.md).

Implementation records:

- [Phase 1 — terminology-safe domain types](PHASE1.md)
- [Phase 2 — tomb references and locked resources](PHASE2.md)
- [Phase 3 — hybrid-PQ identity layer](PHASE3.md)
- [Phase 4 — SOPS artifact engine](PHASE4.md)
- [Phase 5 — decree and seeker authorization](PHASE5.md)
- [Phase 6 — CLI replacement](PHASE6.md)
- [Phase 7 — superseded implementation and documentation removal](PHASE7.md)
- [Phase 8 — security review and release](PHASE8.md) *(clean release commit pending)*

These records describe the replacement architecture. The existing CLI remains the discarded MVP until later implementation phases remove it.
