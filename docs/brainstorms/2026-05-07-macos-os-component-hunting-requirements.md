---
date: 2026-05-07
topic: macos-os-component-hunting
---

# macOS OS Component Hunting Requirements

## Summary

Extend the macOS Reversing Station so it can support first-class macOS operating-system component research while preserving the current bundle-first workflow for third-party applications. The station should guide an operator through a balanced target ladder, build strong workflows across macOS internals in phases, and keep exploitability, chainability, and PoC handoff at the center of finding evaluation.

---

## Problem Frame

The station currently supports app bundles, helpers, XPC services, frameworks, and bare binaries well enough for third-party application research. OS-component hunting adds a different operating shape: Apple-signed binaries, launchd-managed services, PrivateFramework dependencies, SIP/debugging constraints, OS build drift, crash-prone daemons, system/network extensions, DriverKit or IOKit-adjacent components, and sensitive privacy/security subsystems.

The operator also needs a practical target-selection path. A useful first target should exercise the station without immediately forcing the hardest Apple-signed or EDR-specific constraints. A longer target queue should support months of research without turning the template repo into a private target dossier. When the station finds promising behavior, the desired output is not just a static note: it should help rate exploitability, identify chaining opportunities, and transition private lab projects toward PoC development.

---

## Actors

- A1. Operator: The human reverser who selects targets, authorizes lab actions, makes exploitation-safety decisions, and validates findings.
- A2. Cursor agent: The assistant that performs intake, recommends workflows, maintains project state, and proposes next hypotheses.
- A3. Watch: The station's static-analysis decision layer that turns inventory and first-pass facts into routing recommendations.
- A4. Lab VM: The isolated disposable macOS environment used for Ghidra, LLDB, DTrace, launchd/log inspection, and dynamic checks.
- A5. Future planner: The downstream planning workflow that turns these requirements into concrete station changes.

---

## Key Flows

- F1. Third-party shakedown target
  - **Trigger:** The operator wants to validate the full station workflow on a real application before harder OS or EDR targets.
  - **Actors:** A1, A2, A3, A4
  - **Steps:** The operator clones a fresh station project, intakes a source-available enterprise app, lets Watch classify surfaces, follows the recommended recipes, and records evidence in project state.
  - **Outcome:** The operator proves that source-binary correlation, Electron or app-specific review, dynamic confirmation, and handoff records work together.
  - **Covered by:** R1, R2, R7, R8

- F2. Enterprise/security-agent target
  - **Trigger:** The operator moves from general enterprise apps to a security-agent lab target selected from the local target queue.
  - **Actors:** A1, A2, A3, A4
  - **Steps:** The station emphasizes lab isolation, tamper-protection awareness, privileged-service mapping, policy/configuration stores, action logging, and snapshot-friendly handling for disruptive VM actions.
  - **Outcome:** Security-agent research receives first-class routing without treating broad entitlements or protected behavior as proof of vulnerability.
  - **Covered by:** R3, R7, R9, R10, R11, R13

- F3. Apple OS-component target
  - **Trigger:** The operator selects an Apple app bundle, daemon, XPC service, framework, PrivateFramework, or OS subsystem for OS-component research.
  - **Actors:** A1, A2, A3, A4
  - **Steps:** The station inventories launchd metadata, MachServices, entitlements, framework dependencies, SIP/debugging constraints, OS build identifiers, logging expectations, and snapshot-friendly dynamic paths before recommending a recipe; when Apple has published source for the component, it pulls from opensource.apple.com into the local source-binary correlation lane.
  - **Outcome:** OS-component research starts from component topology and lab constraints rather than treating every target as a normal app bundle, and benefits from Apple-published source when available without losing binary primacy.
  - **Covered by:** R4, R5, R6, R9, R10, R11, R12, R13, R22

- F4. Exploitability, chain discovery, and PoC authoring
  - **Trigger:** A static or dynamic finding looks reachable, impact-bearing, or useful as part of a chain.
  - **Actors:** A1, A2, A3, A4
  - **Steps:** The station rates exploitability, surfaces chain candidates from corpus and ontology context, prepares the private-project PoC scaffolding, and guides harness setup, primitive selection, lab state, reliability capture, and evidence linking when the operator transitions to PoC writing inside the same Cursor environment.
  - **Outcome:** The operator can move directly from a confirmed finding into authoring a PoC without losing evidence, assumptions, or next experiments, with chain context captured alongside the primary finding.
  - **Covered by:** R15, R16, R17, R18, R23, R24

- F5. Long-term private target queue
  - **Trigger:** The operator wants a large list of possible targets to work through over time.
  - **Actors:** A1, A2
  - **Steps:** The station provides a local, gitignored target queue with ranking cues and categories while the tracked repo keeps only generic workflow requirements.
  - **Outcome:** The operator has a practical research backlog without committing private target prioritization into the reusable station template.
  - **Covered by:** R19, R20

---

## Requirements

**Target Ladder**
- R1. The station should recommend a configurable first workflow shakedown target that is enterprise-relevant, source-available or source-adjacent, package-rich, and lower-friction than Apple OS daemons or protected EDR agents.
- R2. The station should treat source-available enterprise applications as the preferred first class for validating source-binary correlation and packaged-artifact review.
- R3. The station should treat enterprise/security agents as a high-priority validation class when the operator has an isolated lab for that product family.
- R4. The station should define a progression from safer third-party targets to enterprise/security agents, then Apple app bundles, Apple daemons/frameworks, and finally future iOS support.

**OS Component Support**
- R5. The station should recognize all major macOS-internals target shapes from the start, including app bundles, command-line tools, launchd jobs, MachServices, XPC services, frameworks, PrivateFrameworks, system extensions, network extensions, Endpoint Security clients, DriverKit or IOKit-adjacent components, agents, and daemons.
- R6. The station should build strong workflows for macOS internals in phases, with planning responsible for sequencing coverage so early workflows are deep enough to use on real targets.
- R7. Each macOS-internals phase should distinguish full recipes, basic inventory support, and manual-route-needed targets so the station does not overclaim maturity for a subsystem.
- R8. OS-component workflows should account for Apple-signed binary constraints, SIP/debugging limitations, OS build/version drift, architecture slices, dyld shared cache dependencies, crash risk, and the need for disposable lab state.
- R9. Watch should route OS-component targets from observed surfaces first, then assign one or more families or lanes only after inventory evidence exists.
- R10. The workflow should preserve the existing bundle-first project start where it applies, but should not force OS daemons or framework targets into app-only assumptions.

**Research Safety And Evidence**
- R11. The station should treat the lab VM as disposable and allowed for dynamic research actions, including attaching debuggers, restarting services, sending XPC traffic, resetting TCC state, modifying keychains, and crash-prone behavior.
- R12. The station should keep a durable log of VM-side dynamic actions and outcomes so the operator can reconstruct what changed, what broke, and what evidence was produced.
- R13. The station should prefer or recommend a VM snapshot before high-disruption actions, while accepting that breaking the VM is an expected research outcome.
- R14. The station should require explicit operator approval before performing actions on the workstation or other non-disposable host environment.
- R15. Evidence expectations should distinguish static suspicion, reachability, trust-boundary proof, impact, exploitability, chainability, PoC readiness, and root cause so broad privileges or service exposure are not mistaken for vulnerabilities.

**Exploitability, Chaining, And PoC Handoff**
- R16. The station should rate candidate vulnerabilities by exploitability, including attacker position, prerequisites, controllability, reliability, impact, affected privilege or trust boundary, and remaining proof gaps.
- R17. The station should explicitly look for vulnerability chains by connecting primitives such as sandbox escapes, TCC or privacy bypasses, helper authorization gaps, file-write primitives, keychain trust issues, updater trust failures, and privileged execution opportunities.
- R18. The station should provide private-project scaffolding for PoC transition, including a place to record candidate primitives, chain hypotheses, PoC status, required lab state, artifacts, and next experiments.

**Target Queue**
- R19. The station should support a long local target queue that is gitignored by default, suitable for private research prioritization and iterative target selection.
- R20. The target queue should organize candidates by enterprise relevance, finding-rate potential, workflow coverage, lab safety, and learning value.

**Future iOS Lane**
- R21. The station should name iOS reversing as a future goal without mixing iOS requirements into the immediate macOS implementation.

**Apple Source Integration**
- R22. When Apple has published source for a component (for example via https://opensource.apple.com/releases/), the station should pull it on demand into a workstation-local cache, feed it through the existing source-binary correlation lane, and keep the shipped binary as the authoritative source of truth.

**PoC Authoring And Chain Discovery**
- R23. The station should provide a chain-discovery workflow that uses corpus state, candidate findings, and ontology classes to surface plausible vulnerability chains so chaining stays a first-class outcome rather than an afterthought.
- R24. The station should provide a PoC authoring workflow the same Cursor agent can run when switching models for harder generation tasks, covering harness setup, primitive selection, chain composition, lab state preparation, reliability capture, and evidence linking back to Scriptorium.
- R25. The station should ship a recent-macOS-CVE survey research note that informs ontology coverage, subsystem maturity prioritization, exploitability rating dimensions, and seed chain examples, without becoming a set of per-CVE rediscovery walkthroughs.

---

## Acceptance Examples

- AE1. **Covers R1, R2, R4.** Given the operator wants the first real workflow test, when the station suggests a target, it recommends a configurable source-available or source-adjacent enterprise app ahead of protected EDR agents and Apple OS daemons while explaining the workflow coverage and lower setup friction.
- AE2. **Covers R3, R11, R12, R13, R15.** Given the operator selects an enterprise/security agent in an isolated lab VM, when the station routes the work, it treats that class as in scope while logging VM-side dynamic actions, recommending snapshots before disruptive checks, and preserving evidence discipline.
- AE3. **Covers R5, R6, R7, R8, R9, R10, R14, R22.** Given the operator selects an Apple daemon, PrivateFramework, extension, or other macOS-internals target, when intake and Watch run, the station records OS-component facts and maturity level instead of assuming a normal `.app` bundle, asks before any action would affect the workstation or another non-disposable host, and surfaces matching Apple-published source when available.
- AE4. **Covers R16, R17, R18, R23, R24.** Given a candidate has reachability and impact evidence, when the station evaluates it and the operator transitions to PoC writing, the station records exploitability, surfaces chain candidates, opens PoC scaffolding, and guides harness setup, lab state, and reliability capture without losing evidence.
- AE5. **Covers R19, R20.** Given the operator wants a long target list to work through over time, when the target queue is created, it remains local and ignored while still being useful for prioritization.
- AE6. **Covers R21.** Given iOS reversing is discussed, when scope is finalized, iOS is captured as future direction rather than included in the immediate macOS implementation.
- AE7. **Covers R25.** Given the recent-macOS-CVE survey is run, when planning subsystem maturity, the station uses survey findings to validate ontology coverage and prioritize which subsystems get full recipes versus inventory or manual routing.

---

## Success Criteria

- The operator can move from a configurable enterprise shakedown target to an enterprise/security agent, then to Apple app bundles and deeper OS components without needing to invent a new workflow at each step.
- The station can explain why a target is recommended, what surfaces it will exercise, and what evidence would make a finding worth escalation.
- OS-component targets receive explicit handling for launchd, MachService, framework, PrivateFramework, extensions, dyld shared cache, SIP, OS build, VM action logging, snapshot guidance, and host-action approval.
- The macOS-internals track is not considered complete until all major listed internals have at least an honest maturity level and either a strong workflow, basic inventory support, or a clear manual-routing path.
- Candidate findings are rated by exploitability and chainability, and promising candidates have a clear in-Cursor path from finding to authored PoC.
- Chain discovery and PoC authoring have explicit workflows the agent can follow, not just freeform prompts.
- A recent macOS CVE survey has informed ontology coverage and subsystem maturity priorities so the lane is grounded in current research rather than guesswork.
- Private target prioritization lives in a local ignored queue, while the tracked station repo remains reusable as a template.
- A downstream planning pass can implement the OS-component lane without having to decide the target ladder, safety expectations, or iOS boundary from scratch.

---

## Scope Boundaries

- Full iOS reversing support is deferred to a later lane.
- The immediate work should not replace the Watchtower vocabulary unless a small naming extension is needed for OS-component routing.
- The station should not claim a vulnerability from broad privileges, interesting entitlements, service exposure, or crashability alone.
- The tracked repo should not become a private target dossier; long target queues and research notes belong in ignored local files or private project clones.
- The station should not treat the workstation or non-disposable host as equivalent to the lab VM; host-side actions require operator approval.
- The station should not claim full workflow maturity for every macOS subsystem until that subsystem has a real recipe or documented manual-routing path.
- The reusable station template should provide PoC and chaining scaffolding plus authoring and chain-discovery skills, but target-specific PoC code, exploit chains, and operational notes belong in private project clones rather than tracked template content.
- The recent-macOS-CVE survey should inform ontology and recipes; it should not turn into a set of per-CVE rediscovery walkthroughs in the tracked repo.
- The reusable station template should not commit Apple source mirrors or large fetched archives; the opensource.apple.com cache is workstation-local and gitignored.

---

## Key Decisions

- First validation rung: a configurable enterprise-relevant app that exercises source-binary correlation, packaged-artifact review, extension or plugin surfaces, and update-adjacent review with manageable lab friction.
- Second validation rung: an enterprise/security agent, because that class exercises privileged services, protected behavior, policy/configuration stores, and EDR-style evidence discipline.
- OS-component strategy: recognize all major macOS internals up front, then deepen support in phases so each subsystem gets a strong workflow rather than a shallow checklist.
- OS-component routing strategy: inventory first, family/lane second, because Apple components often span bundles, daemons, frameworks, extensions, and launchd services rather than fitting one app-family label.
- Finding evaluation strategy: exploitability, chainability, and PoC readiness are primary outcomes, not afterthoughts.
- PoC authoring strategy: PoC writing happens in the same Cursor workstation with a model selection chosen for harder generation tasks; the station ships authoring guidance, not just handoff packaging.
- Chain-discovery strategy: a dedicated workflow surfaces chain candidates from corpus state and ontology classes, since chaining is a primary outcome rather than an emergent side effect.
- CVE survey strategy: ship a recent-macOS-CVE survey research note that informs ontology coverage and subsystem maturity priority; do not turn it into per-CVE rediscovery walkthroughs.
- Apple source strategy: pull from opensource.apple.com on demand into a workstation-local gitignored cache fed into the source-binary correlation lane, because that lane already runs workstation-side and a local cache avoids two-host sync and stale full mirrors. Operators who want it on the lab VM can rsync from the workstation cache.
- Target backlog handling: keep the long queue local and gitignored, because the station repo is a reusable template.
- iOS strategy: mention future support in the public README, implement later, because mixing macOS and iOS requirements would blur the immediate planning pass.

---

## Dependencies / Assumptions

- The operator has isolated disposable lab VMs suitable for enterprise/security-agent and OS-component research.
- The operator will clone the station fresh for real target work and keep this repository as the development/template source.
- Apple OS-component dynamic work may require lab VM profiles with different SIP, crash-testing, snapshot, and debugging settings.
- Target selection should favor useful learning and high-signal evidence over immediately jumping to the most protected target.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R5, R6, R7][Needs research] Which macOS-internals target shapes should receive full recipes first, and which should start at basic inventory or manual-route-needed maturity?
- [Affects R8, R9, R10][Technical] Which existing skills should be extended versus which new OS-component skills should be added?
- [Affects R9, R10][Technical] How should Watch represent OS-component lanes and maturity levels without overfitting to a fixed list of Apple subsystems?
- [Affects R12, R13][Technical] What action-log and snapshot conventions should be used before high-disruption VM-side checks?
- [Affects R16, R17, R18][Technical] What private-project artifact shape should carry exploitability ratings, chain hypotheses, and PoC transition state?
- [Affects R19, R20][Technical] What lightweight format should the local target queue use so agents can update and sort it without turning it into project state?
- [Affects R22][Technical] What directory and naming convention should the workstation-local Apple source cache use, and should the fetcher be a script in `scripts/` or a skill that wraps the existing source-binary correlation lane?
- [Affects R23, R24][Technical] What workflow steps and output shapes should the chain-discovery and PoC authoring skills define, and how do they integrate with Watch decision support, Scriptorium anchors, and CORPUS rows?
- [Affects R25][Needs research] Which recent macOS CVEs and subsystems should the survey cover to maximize ontology validation and subsystem maturity input without sliding into per-CVE rediscovery?
