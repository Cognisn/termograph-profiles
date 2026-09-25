# Contributing a profile

## Before you start

**Publish declarations, never data.** A profile describes how a platform lays
its data out — field names, table joins, analyser chains. It must not contain
case content, custodian names, document text, tags from a real matter, or
anything else drawn from evidence. Export strips validation verdicts
automatically; it does not and cannot strip a field name you have typed by
hand that happens to name a custodian.

## The flow

1. Build and validate the profile on your own Termograph instance, against a
   real case of that platform. A profile that has never been validated is not
   worth publishing.
2. **Profiles → Export** produces an unsigned `.tgprofile` bundle.
3. Fork this repository, add the bundle under `bundles/`, and open a pull
   request.
4. On merge, the pipeline validates the bundle, signs it, and updates
   `index.json`.

You do not sign anything yourself, and you do not edit `index.json` — the
pipeline owns it. A pull request that modifies `index.json` will be asked to
revert that file.

## What reviewers look for

- **No evidence data.** The first and most important check.
- **A real platform.** Profiles describe a class of case, not one case.
- **Provenance that makes sense.** The provider field should identify you or
  your organisation honestly.
- **Validation.** Say in the pull request which platform version you
  validated against and what you ran. "Validated family expansion and item
  identity against Nuix 7.6 with 8 stores" is worth more than a green tick.
- **Scope.** A profile that fills every slot is more useful than one that
  fills none, but a partial profile is welcome and Termograph tells operators
  what is missing.

## Versioning

Bundles are versioned in their manifest. Publishing an improved profile for a
platform means a new version, not an edit of the old one — deployments that
imported the old version keep working, and can choose to update.

## Licence

By opening a pull request you agree that the profile may be redistributed
from this repository to any Termograph deployment. Profiles contain
declarations about publicly documented data formats; if you believe a
profile encodes something proprietary to your organisation, do not publish
it here.
