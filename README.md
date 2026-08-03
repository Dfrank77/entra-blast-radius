# entra-blast-radius

> **Under active development.** Core reachability works; owned-app permission weighting and an HTML report are next.

Given a single Entra ID identity, compute the complete set of everything it can reach and rank it by the worst privilege at the end.

## Why

Every identity and incident-response team faces the same question when an account is compromised: *how bad is it?* Native Entra has no single answer. Effective access is scattered across direct role assignments, nested group memberships, PIM-eligible roles, and app ownership, and no one screen ties them together.

This is the inverse of an attack-path scan. An attack-path scan asks "who can reach the crown jewels?" and walks toward privilege. Blast radius starts from one identity and walks outward: if this account is compromised, what does the attacker now control?

## What it computes

For a given principal (by UPN or object id):

- **Direct role assignments** the principal holds.
- **Group memberships**, nesting included (Graph `transitiveMemberOf` resolves nested groups server-side).
- **Roles granted through those groups** — the reach that group membership actually confers.
- **PIM-eligible roles**, direct or via a group — dormant privilege an attacker can activate.
- **Owned applications** — owning an app means controlling its permissions, which can exceed the owner's own roles.

Every reachable item records *how* it is reached, so the output explains itself.

The result is ranked worst-first, with the single most dangerous reachable privilege called out as the headline.

## Usage

```
pip install -r requirements.txt
python blast_radius.py <UPN-or-object-id>
```

Example:

```
python blast_radius.py jane@contoso.com
```

Authenticates interactively (browser sign-in) using delegated read permissions.

## Roadmap

- Weight owned-app permissions into the "worst reachable" ranking (an owned app holding `RoleManagement.ReadWrite.Directory` is effectively tenant takeover, even if the owner holds no such role directly).
- HTML report matching the Entra security suite.
- Tenant-wide mode: every principal ranked by blast radius.
- Used-vs-standing: fold sign-in / audit data to separate active reach from dormant reach.

## Part of a suite

Built on the shared model behind [entra-attack-path-visualizer](https://github.com/Dfrank77/entra-attack-path-visualizer) and the [entra-orchestrator](https://github.com/Dfrank77/entra-orchestrator) correlation suite.
