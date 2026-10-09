# conformance-py

An independent verifier for VOAF spec release 2.1.0 (`spec/2.0/preimage.md`,
format tag `voaf-2.0`), written in Python 3 with the standard library only. It
sits beside the reference verifier as a second implementation of the same text.

## Provenance

- **Who wrote it.** A separate session, given only the spec text and the test
  vectors (`spec/2.0/preimage.md` and `spec/2.0/test-vectors.json`), wrote it
  first at `d42a55f` and then updated it at `08f06db`.
- **What it never read.** It never read the reference verifier
  (`spec/2.0/reference-verifier.rs`, `verifier/`) or any Vigil code.
- **What it did read.** While writing and updating these files, every file it
  and its review agents read was one of the two spec files or one of the files
  here, all inside that session's folder. The recorded exceptions are below; none
  of them is spec text, reference code or Vigil code.
  - The session once read back its own `run_vectors.py` output, which it had
    redirected to `/tmp`, and then deleted that file.
  - After the first version was finished, the session read its review agents'
    transcripts under `~/.claude`, at the user's request, to list the files
    those agents had read.
  - The review agents ran commands from `/tmp`, `/private/tmp` or the home
    directory and wrote to `/dev/null` and `/dev/full`. One ran `/bin/sh`, and
    some passed nonexistent paths to the verifier to test its errors. Their
    transcripts record no other path outside the folder.
  - The `08f06db` update ran no agents.
  - Adding it to this repository, the session read this repository's `vectors`
    workflow, `docs/2.1.1-errata.md` and the pull request description, and
    checked the spec files' hashes. It did not open the reference verifier or
    `verifier/`.
- **Where its choices are recorded.** `NOTES.md` records the choices it made
  where the text was silent, ambiguous or self-contradictory, quoting section
  and line. It also lists the vectors it disagrees with; none of those
  disagreements changes a hash, a verdict or a code.

## Files

- `voaf_verify.py`: the verifier and its command line (`python3 voaf_verify.py
  DOCUMENT [--json]`). NOTES.md section 1 gives the exit codes.
- `run_vectors.py`: runs every vector, every negative vector and every negative
  document, then a block of derived checks for rules no vector covers. It prints
  one PASS or FAIL line per check and exits non-zero on any failure.
- `NOTES.md`: the choices above.
- `SHA256SUMS`: the hashes of those three files as the session left them.

These three files are copied unchanged from that session's folder. Do not edit
them: CI checks `SHA256SUMS`. A change to the spec that they must follow goes
back through an isolated session.

## Running it

`run_vectors.py` looks for the vectors beside itself, at
`spec/2.0/test-vectors.json` relative to its own directory, not the working
directory. CI links `conformance-py/spec` to the repository's `spec/` before it
runs. Locally:

```
ln -s ../spec conformance-py/spec      # once; not committed
python3 conformance-py/run_vectors.py
```

At `08f06db` every line passes and it exits 0. That is 63 vector lines (24
positive vectors, 22 negative vectors, 13 negative documents, two genesis cases,
the chain walk and `field_counts`) and 18 derived lines.
