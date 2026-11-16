# Privacy and Evidence Handling

- Source evidence and case outputs stay under the configured local Aries root, normally `C:\Aries`.
- The web console binds to `127.0.0.1` by default.
- Evidence is not uploaded to this repository or an Aries-operated cloud service.
- Text sent to the configured AI provider can contain case-derived excerpts, filenames, indicators, questions, and analyst context. Provider handling depends on the provider and account you configure.
- Do not use a third-party model provider for evidence that your legal, contractual, or organizational rules prohibit from leaving the workstation.
- Case exports and diagnostics intentionally exclude source evidence and recovered bulk content, but analysts must inspect every bundle before sharing it.
- Deleting a case is destructive. Preserve required originals and legal records separately.
