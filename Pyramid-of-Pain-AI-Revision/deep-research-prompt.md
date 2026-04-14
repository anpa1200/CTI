# Deep Research Prompt: The Pyramid of Pain in the AI Age

> Use this prompt with a deep research tool (Perplexity Deep Research, ChatGPT Deep Research, Gemini Deep Research, or equivalent).

---

```
DEEP RESEARCH PROMPT: The Pyramid of Pain in the AI Age — A Required Revision

RESEARCH OBJECTIVE
Assess whether David Bianco's Pyramid of Pain (2013) remains structurally valid as a 
detection prioritization framework given the operational capabilities introduced by 
large language models, AI-assisted code generation, and autonomous agent toolchains 
as of 2024–2025. If the framework requires revision, propose a concrete updated model.

---

BACKGROUND (do not summarize — use as context only)

Bianco's original pyramid ranks IOC types by the cost they impose on an adversary 
when detected and blocked:
  Hash values → IP addresses → Domain names → Network/host artifacts → Tools → TTPs

The core argument: TTPs are at the top because changing how an actor fundamentally 
operates is expensive. Detection at the TTP layer is the most durable.

The question: does AI change the cost structure of this hierarchy?

---

RESEARCH QUESTIONS (address each explicitly)

1. TOOL LAYER COLLAPSE
   "Vibe coding" (LLM-assisted code generation) allows a motivated actor to generate 
   functional malware, C2 frameworks, or exploit code from natural language prompts 
   with minimal reverse-engineering skill. 
   - How fast can a novel, functional offensive tool be generated from scratch using 
     current LLMs (GPT-4o, Claude, Gemini, local models)?
   - Does LLM-assisted tool generation effectively reduce the "Tools" layer cost to 
     near-zero, collapsing it toward the bottom of the pyramid?
   - What documented threat actor behavior (2023–2025) supports or contradicts this?
   - Is tool uniqueness (and thus hash uniqueness) now trivially achievable per-operation?

2. TTP LAYER DURABILITY
   If an AI agent can autonomously select, adapt, and combine techniques based on 
   environmental feedback, does the TTP layer remain the most stable detection surface?
   - Are there documented cases of AI-assisted adversaries dynamically adapting TTPs 
     mid-operation in response to detection signals?
   - How does autonomous LLM-based attack orchestration (e.g., PentestGPT, AutoAttack 
     research, ReAct-based agents) affect TTP consistency across campaigns?
   - Can an AI-driven attacker use different TTPs for each target while achieving the 
     same strategic objective — and if so, what does detection target?

3. NEW LAYERS ABOVE TTPs
   If TTPs become more fluid, what sits above them? Candidates:
   - Strategic intent / mission objective (what the actor is trying to achieve)
   - Cognitive/reasoning patterns of the AI system used (model fingerprinting)
   - Operational tempo and decision timing (AI agents operate faster than humans)
   - Infrastructure acquisition patterns (how the actor provisions resources)
   - Prompt injection and LLM-specific attack patterns as a new TTP class
   Research question: Are any of these more stable, more detectable, and more costly 
   to change than TTPs in an AI-assisted operation?

4. DETECTION CAPABILITY ASYMMETRY
   AI also enhances defenders. Assess the asymmetry:
   - Where does AI give attackers the larger relative advantage in the cost structure?
   - Where does AI give defenders the larger relative advantage (e.g., behavioral 
     baselining at scale, anomaly detection, automated rule generation)?
   - Does AI compress the defender's detection engineering cycle enough to offset the 
     attacker's tool-generation advantage?

5. EMPIRICAL EVIDENCE BASE
   Survey documented AI-assisted threat actor activity (2023–2025):
   - Which threat groups have confirmed or credibly alleged AI tool usage?
   - What specific capabilities were enhanced (phishing, malware generation, 
     reconnaissance, vulnerability research, C2 communication)?
   - CISA, NSA, NCSC, Europol, Mandiant, CrowdStrike, Microsoft MSTIC reporting.
   - UN Panel of Experts and academic red-team research.

6. PROPOSED REVISED FRAMEWORK
   Based on findings, propose a revised pyramid or alternative model:
   - Preserve what remains structurally valid from Bianco's original.
   - Identify which layers have collapsed (cost reduced to near-zero by AI).
   - Propose new layers or renamed layers that reflect current cost realities.
   - Address whether a linear hierarchy is still the right shape, or whether a 
     different structure (e.g., matrix, dynamic cost graph) better represents 
     AI-era detection economics.

---

SOURCES TO PRIORITIZE

Primary:
- CISA/NSA/NCSC joint advisories on AI-enabled threats (2024–2025)
- Microsoft MSTIC threat intelligence reports mentioning AI-assisted actors
- Mandiant / Google Threat Intelligence Group AI threat reporting
- CrowdStrike Global Threat Report 2024, 2025
- Europol report on AI and cybercrime (2024)
- ENISA Threat Landscape 2024
- Academic: arXiv papers on LLM-assisted penetration testing, autonomous attack agents
- OpenAI, Anthropic, Google safety team reports on model misuse in offensive operations

Secondary:
- Bianco's original 2013 paper (baseline)
- SigmaHQ, MITRE ATT&CK v15+ for TTP taxonomy updates
- Recorded Future, SANS, Krebs on Security for practitioner perspective
- DEF CON / Black Hat 2023–2025 presentations on AI-assisted offense

---

OUTPUT FORMAT REQUIRED

1. EXECUTIVE SUMMARY (300 words max)
   One-paragraph answer to: "Does the Pyramid of Pain need revision in the AI age, 
   and if so, what is the single most important structural change?"

2. LAYER-BY-LAYER COST ANALYSIS TABLE
   For each original pyramid layer: estimated attacker cost (pre-AI vs. post-AI), 
   evidence quality (high/medium/low/speculative), and defender detection durability.

3. EMPIRICAL EVIDENCE REGISTER
   Documented incidents or research findings supporting cost-structure changes, 
   with source, date, and confidence level.

4. PROPOSED REVISED MODEL
   Named, described, and justified. Include what is preserved, what is changed, 
   and what is new. If a linear hierarchy no longer fits, explain why and propose 
   an alternative structure with rationale.

5. OPEN QUESTIONS
   What remains genuinely unknown or contested? What research would resolve it?

6. IMPLICATIONS FOR DETECTION ENGINEERING
   Concrete recommendations: which detection investments become less valuable, 
   which become more valuable, and what new detection categories should be built.

---

CONSTRAINTS

- Do not summarize Bianco's original paper beyond what is needed for contrast.
- Distinguish clearly between documented fact, credible inference, and speculation.
- Do not conflate AI-assisted attacks (human using AI tools) with autonomous AI 
  attacks (AI agent operating independently) — these have different cost structures.
- Flag any finding where the evidence base is thin or primarily from vendor 
  marketing rather than independent research.
```
