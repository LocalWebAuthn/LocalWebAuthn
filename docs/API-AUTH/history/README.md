# Superseded design notes

**None of these describe the shipped system.** The design is
[`docs/API-AUTH.org`](../../API-AUTH.org); read that instead. These are kept because the
reasoning that produced it is more useful than the conclusion alone — three of the
restrictions in the shipped feature exist because an earlier draft here got them wrong.

Each was written before the code existed and none has been updated since. Where one
contradicts `API-AUTH.org`, `API-AUTH.org` is right.

| File                                                                 | What it was                                                                                         |
| -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [`DESIGN-MACHINE-CREDENTIALS.md`](DESIGN-MACHINE-CREDENTIALS.md)     | First design. Establishes the `kind` column and the "only server-chosen facts are controls" rule.   |
| [`DESIGN-MACHINE-CREDENTIALS-2.md`](DESIGN-MACHINE-CREDENTIALS-2.md) | Second treatment, from a different starting point.                                                  |
| [`DESIGN-MACHINE-CREDENTIALS-3.md`](DESIGN-MACHINE-CREDENTIALS-3.md) | Third treatment.                                                                                    |
| [`CONSENSUS.md`](CONSENSUS.md)                                       | Reconciles the three and surveys the standards — RFC 9449 (DPoP), RFC 9421, RFC 9729, OAuth drafts. |
| [`PROVISIONING.md`](PROVISIONING.md)                                 | The bootstrap-token provisioning flow, superseded by `API-AUTH.org` §"Provisioning".                |

Two things in here are still worth reading on their own terms:

- `CONSENSUS.md`'s standards survey, including **why RFC 9729 was ruled out** and why the
  OAuth first-party-apps draft does not fit. That reasoning is not repeated in
  `API-AUTH.org`, which states the conclusion.
- `DESIGN-MACHINE-CREDENTIALS.md`'s framing of what a hostile key holder can forge, which is
  the argument the whole feature rests on.

`PROVISIONING.md` in particular says "as shipped, `@localwebauthn/server@2.2.0` has no
`kind` column" — true when written, and the clearest single marker that these files are a
record of the past rather than documentation.
