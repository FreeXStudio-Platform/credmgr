# Support CredMgr

CredMgr is free to use today under its source-available licence ([LICENSE](LICENSE)), has no
telemetry, and nothing in the current version is locked behind a payment. Future versions may be
paid. It is built and maintained by the [FreexStudio](https://freexstudio.com) team. Donations are
asked for at most three times, at entry milestones, in a dismissible reminder you can turn off.
**This page is about voluntary donations.** A donation is a gift: it buys no rights, no support and
no promise of any feature, and it does not make any future version free.

If it saved you from a leaked key — or from a `.env` file in a public repo — you can support
the work.

> **Do not send anything to a CredMgr address you found anywhere other than a signed release
> of this repository.** Verify against the tagged release, not a screenshot, not a search
> result, and not a message from anyone claiming to be the maintainer.

## Crypto

| Chain | Address |
|---|---|
| **EVM** (Ethereum, BNB Chain, Arbitrum, Optimism, Base) | `0x63AD9e7a8f0451bc2b8D03B3B473935F9482A3C9` |
| **Bitcoin** (BTC, native segwit) | `bc1qxwkq4jgu4wen62wpqkmx3yx6x9zcv8gvl3vydt` |
| **Solana** | `i6SffLGEcaRgtSTbrktGJUjxxcWqe7hRFfRd88dCDEb` |
| **Tron** (TRC-20) | `TVeDpvsf6he6vsMQosbeGT4mRZ2hHomz59` |
| **TON** (The Open Network) | `UQD7BTjZDmc3snzUlvRom6xQgGfhua_Jkhelydc8zwix4R3D` |

**Before you send anything:**

1. Check the address against **this file in the signed release tag** you are running.
2. Verify the first and last six characters after pasting. Clipboard-hijacking malware is
   real and it targets exactly this.
3. Send a small test amount first if the sum matters to you.
4. EVM address: same address on every EVM chain listed. **Do not send to it on a chain that
   is not listed.**
5. These are donations. They are **not refundable**, they buy nothing, they grant no licence,
   no support agreement, no priority, and no influence over the roadmap.

## Other ways that help just as much

- **Report a security bug** — see [SECURITY.md](SECURITY.md). Worth more than money.
- **Star the repo.** It is how other people find it.
- **Tell someone** who is still keeping API keys in a Notes file.
- **Write documentation.** Almost always the biggest gap.
- **Test on Linux or Windows** and report what broke.

## What donations do not do

They do not create an obligation to ship anything, do not change the licence, do not buy a licence,
and do not make any future version free. The licence terms, including what a version you already
hold stays under, are in [LICENSE](LICENSE) and apply whether or not you ever donate.

## Transparency

There is no treasury, no DAO, no token, and no fundraising target. Donations go to
FreexStudio. CredMgr shows a dismissible reminder at most three times in the life of an install: after an unlock once the vault holds 50 entries and has been unlocked on 14 different days, then at 150 entries and 45 days, and at 300 entries and 90 days. It is never shown over a dialog, while the vault is locked, in a game, or twice in one day, it steps aside from the control you are using, and "don't remind me" turns it off for good. Counting days stores a calendar date only, on your machine. The cosmetic extras (alternate marks, node glyph weight, a second halo, a header badge, node shapes, node and link colours, an entry-dot palette, a graph backdrop, an unlock flourish and a CredPong ball trail) ship inside the app, encrypted. A supporter code, sent by e-mail after a donation, opens them on your device once; nothing is sent or fetched. **To ask for a code, send your transaction hash (the public id of your transfer; never a key or seed phrase) as proof to Admin@freexstudio.com.** **Nothing functional is ever gated**, and every feature works without a donation or a code (ADR-082).

---

*CredMgr is published by **FreexStudio**. See [TRADEMARKS.md](TRADEMARKS.md).*
