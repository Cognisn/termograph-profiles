# Termograph profile library

Signed, portable **collection profiles** for [Termograph](https://github.com/Cognisn/termograph).

Termograph ships with no profiles and no detectors. It is an engine; the
knowledge of how a particular platform lays its data out — Nuix, Intella,
Elastic, a bespoke DMS — lives in a profile, and profiles live here.

## What a profile is

A collection profile is everything Termograph needs to make one family of
cases searchable:

| Component | What it does |
|---|---|
| detector | recognises the platform from the file layout |
| pairing | how Lucene fields join to the tables of the paired database |
| inference chain | the analyser chain behind each field — tokeniser, filters, order |
| scripts | declarative query-plan steps that traverse database tables |
| column profiles / column names | which columns are read, and what they are called |
| skills | guidance that shapes the AI assistant for this platform |
| canned prompts | starting questions that make sense for this data |

A profile need not carry all of them. Anything it omits, the operator
generates themselves — Termograph tells them which pieces are missing and
which analysis produces them.

## Using a profile

From inside Termograph: **Profiles → Community**, then Install. The product
downloads the bundle, verifies its signature and hashes, and imports it.

Offline or air-gapped: download the `.tgprofile` file from `bundles/` and use
**Profiles → Import**. Verification is entirely offline — there is no call
home, and no transparency log to reach.

## Trust

Bundles published here are signed by Cognisn as part of the merge pipeline.
Termograph verifies that signature on import and shows the verified identity
against the profile.

A bundle that is **not** signed still imports — sharing a profile with a
colleague by email should not require a pull request — but it carries a
persistent warning on the profile and on every collection bound to it.

**A signature says where a profile came from. It does not say the profile is
correct for your data.** Termograph strips every validation verdict from a
bundle on import, so an imported profile always arrives unvalidated and you
must run family, item-identity and attribute validation against your own case
before relying on it. In a legal matter, a confidently wrong profile is worse
than no profile.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: export a profile from your
own Termograph instance, open a pull request adding it under `bundles/`, and
the merge pipeline signs it and updates the index.

## Layout

```
index.json          the catalogue Termograph reads
bundles/            signed .tgprofile files
```

## Licence

Profiles contributed here are published under the terms in
[CONTRIBUTING.md](CONTRIBUTING.md). They contain declarations about data
layout, not data: **never include case content, custodian names, or anything
drawn from a real matter in a profile you publish.**
