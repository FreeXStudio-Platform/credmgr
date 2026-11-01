# Acknowledgements

CredMgr stands on other people's work.

## Cryptography

- **[age](https://github.com/FiloSottile/age)** — Filippo Valsorda and Ben Cartwright-Cox.
  V1 encrypts every value with `age` (X25519 + ChaCha20-Poly1305). The design goal of age —
  a file encryption tool with no configuration knobs to get wrong — is the reason this project
  did not roll its own format.
- **[RFC 6238 (TOTP)](https://datatracker.ietf.org/doc/html/rfc6238)** and
  **[RFC 9180 (HPKE)](https://datatracker.ietf.org/doc/html/rfc9180)**, whose
  DHKEM(X25519, HKDF-SHA512) construction shapes the V2 envelope.
- **[BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)** — the wordlist
  used to recognise recovery phrases.

## Runtime and tooling

- **[Node.js](https://nodejs.org)** and its `crypto` module.
- **[Express](https://expressjs.com)** — the local dashboard API in V1.
- **[Model Context Protocol](https://modelcontextprotocol.io)** — Anthropic. MCP is why an
  AI agent can hold a scoped capability instead of a copy of your `.env`.

## Design

- The document design system, the token architecture, and the vendored force-directed graph
  approach were adapted from an internal design system by the same author. Structure and
  discipline were carried across; no third-party brand asset was.
- **[force-graph](https://github.com/vasturiano/force-graph)** — Vasco Asturiano (MIT). The
  canvas graph engine behind the V2 node view.
- **[d3-force](https://github.com/d3/d3-force)** — Mike Bostock, under force-graph.
- **[Inter](https://rsms.me/inter/)** — Rasmus Andersson (SIL OFL 1.1).
- **[JetBrains Mono](https://www.jetbrains.com/lp/mono/)** — JetBrains (SIL OFL 1.1). The
  vault speaks in monospace, and this is the voice.

## Ideas taken deliberately

- **[Obsidian](https://obsidian.md)** — the graph view. The insight that a *map* of your own
  material is a better home screen than a *list* of it is theirs.
- **[1Password](https://1password.com)** and **[Bitwarden](https://bitwarden.com)** — for
  showing that a credential manager can be pleasant, and for the secret-field ergonomics
  everyone has since copied.
- **[SOPS](https://github.com/getsops/sops)** and **[pass](https://www.passwordstore.org)** —
  for proving that file-based, tool-independent secret storage beats an opaque database when
  the thing you care about most is being able to recover your data in ten years.
- **[Filippo Valsorda's writing on misuse-resistant APIs](https://words.filippo.io)** — the
  reason this project has no cipher suite selector.

## Everyone who reports a bug

Especially security bugs. See [SECURITY.md](SECURITY.md). Contributors are credited in
[CHANGELOG.md](CHANGELOG.md) unless they ask not to be.

---

Full dependency licences: `npm run licenses` (V1) or `Settings → About → Licences` (V2).
If your work is used here and is missing from this list, that is a bug — please open an issue.
