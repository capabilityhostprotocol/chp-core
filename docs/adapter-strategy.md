# Adapter Strategy

Adapters connect CHP to the systems people actually use — filesystems, Git,
GitHub, HTTP APIs, MCP, model servers, schedulers, and more. They are the most
important growth surface in the project, because each adapter is three things at
once:

1. **An integration** — more adapters make CHP more useful.
2. **A distribution channel** — each adapter gives a system's users a reason to
   adopt CHP.
3. **A brand & security surface** — a low-quality or malicious adapter reflects
   on "CHP" as a whole.

The strategy below is designed to maximize the first two while protecting the
third. See [`adapter-authoring.md`](adapter-authoring.md) for the how-to.

## Three tiers

### 1. Open by default (Apache-2.0)

First-party core adapters (in `packages/chp-adapter-*`) and community adapters
(in their own repositories) are Apache-2.0. This tier is the network effect, and
it is never restricted. We invest here in developer experience: the
[`chp-adapter-template`](https://github.com/capabilityhostprotocol/chp-adapter-template)
is the golden path, the authoring guide is kept current, and the conformance
suite gives every author a clear bar to hit.

Anyone can write and publish an adapter. Truthful, descriptive naming
("a CHP adapter for Acme") is welcome — see [`../TRADEMARK.md`](../TRADEMARK.md).

### 2. Commercial (proprietary)

Adapters to enterprise or regulated systems — where the buyer expects vendor
support, certification, and an SLA — may be built and sold by Project Auxo, Inc.
or partners. These live in **private** repositories, are licensed commercially,
and do **not** enter the open core. This is a monetization line that sits on top
of the protocol without restricting it (see [`../GOVERNANCE.md`](../GOVERNANCE.md)).

### 3. Certified (trademark-gated)

The **"CHP-Certified Adapter"** program lets an adapter — open or commercial —
carry a mark that tells adopters it is trustworthy. Certification requires:

- passing the [`../conformance/`](../conformance) suite at a stated version;
- meeting a security & quality bar (input handling, secret hygiene, least
  privilege — reuse the patterns in `chp-adapter-safety` and
  `chp-adapter-secrets`);
- shipping **signed provenance** — and, fittingly, the certification result is
  itself recorded as CHP evidence (the program dogfoods the protocol).

The mark is governed by [`../TRADEMARK.md`](../TRADEMARK.md). Certification may be
offered as a paid program; the conformance suite that underpins it stays open.

## Registry & provenance

The adapter registry (`registry/adapters.json`) is the discovery surface. Over
time it grows from a static catalog into a provenance surface: publisher,
conformance status, certification, and signature for each listed adapter — so an
agent (or a human) can discover not just *that* an adapter exists, but *whether
it can be trusted*.
