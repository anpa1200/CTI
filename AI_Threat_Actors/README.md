# AI in Offensive Operations: How Threat Actors Use Artificial Intelligence

**A rigorous, evidence-based CTI report on the evolution of AI usage by cybercriminal groups, ransomware operators, fraud actors, and state-linked APTs — from the earliest documented cases through April 2026.**

By [Andrey Pautov](https://medium.com/@1200km) — April 2026

> **v2 — Updated April 2026.** Integrated findings from Google Gemini deep research and OpenAI deep research. Added: GTG-2002 agentic data extortion case (Anthropic Aug 2025); SesameOp AI-API-as-C2 (Microsoft Nov 2025); TeamPCP/LiteLLM AI supply chain attack (Mar 2026); ScopeCreep malware (OpenAI Jun 2025); FBI IC3 2025 AI-crime statistics ($893M); Microsoft DDR 2025 figures; Mandiant M-Trends 2026 voice phishing data; Singapore CSA phishing sample data; GTG-1002 dispute/nuance from Intel 471 and Palo Alto Networks; new Technical Evolution Stage 5 (AI APIs as attack infrastructure) and Stage 6 (AI supply chain hijacking); updated Top 10 tables; expanded defender recommendations.

---

## Confidence Scale

All major judgments carry an explicit confidence rating:

- **HIGH** — Multiple independent primary sources; strong corroboration.
- **MEDIUM** — Primary sourcing with some gaps or partial corroboration.
- **LOW** — Single-source, vendor claim, or significant evidentiary uncertainty.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Key Judgments](#2-key-judgments)
3. [Chronological Timeline](#3-chronological-timeline)
4. [Major Incidents](#4-major-incidents)
5. [TTP Analysis (ATT&CK-Aligned)](#5-ttp-analysis-attck-aligned)
6. [Statistics and Measurable Trends](#6-statistics-and-measurable-trends)
7. [Reality vs. Hype](#7-reality-vs-hype)
8. [Actor Segmentation](#8-actor-segmentation)
9. [Technical Evolution](#9-technical-evolution)
10. [Forecast](#10-forecast)
11. [Final Conclusions](#11-final-conclusions)
12. [Top 10 Milestones](#12-top-10-milestones-table)
13. [Top 10 Incidents](#13-top-10-incidents-table)
14. [Defender Recommendations](#14-defender-recommendations)
15. [Source Register](#15-source-register)

---

## 1. Executive Summary

AI has crossed from a theoretical offensive threat into a documented, operationally deployed capability — but the transition has been uneven, slower than vendor narratives suggest, and concentrated in specific use cases rather than across the full kill chain.

**The earliest verifiable documented criminal use of AI in an attack is March 2019**, when voice-cloning software was used to impersonate a German CEO and steal €220,000 from a UK energy company (Euler Hermes insurer, PRIMARY). No primary-sourced confirmed criminal AI attack predates this.

**The pre-ChatGPT period (2019–2022)** was dominated by isolated, high-impact fraud incidents using voice cloning and early deepfakes, and by theoretical demonstrations of generative text for phishing. Criminal adoption was limited by access costs and technical sophistication.

**The ChatGPT era (November 2022–present)** changed accessibility but did not — contrary to widespread claims — immediately produce a wave of AI-powered intrusions. The first major documented milestone was the **February 2024 joint OpenAI/Microsoft disclosure** that five nation-state groups (Russia, China, Iran, North Korea) were using LLMs, assessed as exploratory and producing no novel malware or breakthrough capabilities.

**2025 marks the inflection point.** Five confirmed, primary-sourced developments represent genuine TTP evolution rather than incremental productivity gains:
1. **LAMEHUG / PROMPTSTEAL** (July 2025, CERT-UA / GTIG) — first in-the-wild malware querying an LLM during execution (APT28-attributed).
2. **PROMPTFLUX** (November 2025, Google GTIG) — first malware designed to rewrite its own source code via AI API queries.
3. **GTG-1002** (November 2025, Anthropic) — AI agent conducting 80–90% of an intrusion lifecycle across ~30 targets (disputed by some vendors as overstated autonomy; see §7).
4. **SesameOp** (November 2025, Microsoft) — first confirmed abuse of a legitimate AI API (OpenAI Assistants) as a covert C2/relay channel.
5. **GTG-2002** (August 2025, Anthropic) — Claude Code used as active operator in data extortion targeting 17 organisations including government and healthcare.

**2026 adds a new threat category entirely:** the **AI supply chain**. The March 2026 TeamPCP/LiteLLM attack — trojanizing a dominant AI proxy library on PyPI — demonstrates that the infrastructure connecting enterprises to LLMs is itself a target, separate from AI being used offensively.

Despite these developments, the dominant finding across the best-sourced CTI reports (NCSC, OpenAI, IBM X-Force, Mandiant) remains: **AI is enhancing existing TTPs, not creating new attack categories.** Social engineering, phishing, fraud, and influence operations have seen the most significant practical impact. Autonomous AI-driven intrusion at scale remains nascent.

The sectors most exposed today are financial services, professional services, and critical infrastructure. The actors most advanced in AI adoption are **Iranian APT42**, **North Korean FAMOUS CHOLLIMA**, and **financially motivated BEC/fraud operators**.

---

## 2. Key Judgments

| # | Judgment | Confidence |
|---|----------|-----------|
| KJ-1 | The earliest verifiable documented criminal deployment of generative AI in an attack is March 2019 (voice-cloning CEO fraud). No primary-sourced confirmed case predates this. | HIGH |
| KJ-2 | AI-enabled attacks remain dominated by social engineering, phishing, fraud, and influence operations. Direct AI involvement in intrusion TTPs (exploitation, lateral movement, persistence) is documented but still uncommon. | HIGH |
| KJ-3 | AI is enhancing existing TTPs rather than creating fundamentally new attack vectors. This consensus holds across NCSC, OpenAI, IBM X-Force, and Mandiant reporting through 2024. | HIGH |
| KJ-4 | 2025 represents a genuine inflection point: LAMEHUG, PROMPTFLUX, and GTG-1002 demonstrate that LLM-integrated malware and agentic AI intrusion are no longer theoretical. | HIGH |
| KJ-5 | Fully autonomous, end-to-end AI hacking without meaningful human oversight is unlikely at scale before 2027. The GTG-1002 case required 4–6 human decision points per campaign even at 80–90% AI autonomy. | MEDIUM |
| KJ-6 | Iranian APT42 and North Korean groups (FAMOUS CHOLLIMA, Kimsuky/Emerald Sleet) are the most prolific AI adopters among state-linked actors, with the broadest documented use across multiple attack phases. | HIGH |
| KJ-7 | Ransomware operators have largely not integrated AI into core ransomware TTPs. No primary source confirms AI adoption by LockBit, CL0P, or equivalent groups. Criminal AI adoption is concentrated in fraud/BEC, not intrusion-and-encrypt workflows. | MEDIUM |
| KJ-8 | Most underground "dark LLM" products (WormGPT, FraudGPT, etc.) were effectively vaporware in 2023. Trend Micro found no verified proof of functional capabilities. The real risk is legitimate LLM access via jailbreaks, not custom criminal models. | HIGH |
| KJ-9 | AI lowers the barrier to entry for less-skilled threat actors, particularly for multilingual social engineering, voice cloning, and deepfake-enabled fraud. The measurable result is scale and volume, not necessarily sophistication. | HIGH |
| KJ-10 | The most significant near-term AI-enabled threat for most organizations is AI-enhanced phishing and deepfake-enabled fraud — not AI-powered exploitation. | HIGH |

---

## 3. Chronological Timeline

> **Legend:** CONFIRMED = primary source, directly verified. REPORTED = credible secondary sourcing with primary basis. SUSPECTED/WEAK = single-source, vendor claim, or unverified. AI-ADJACENT = automation or scripting, not specifically AI/ML.

---

### Pre-ChatGPT Era (2004–2022)

| Date | Event | Actor | Country | AI Use | Evidence | Why It Matters |
|------|--------|-------|---------|--------|----------|----------------|
| 2004 | ML spam filter evasion demonstrated at MIT Spam Conference | Academic / implicit criminal adoption | N/A | ML models used to evade ML-based spam filters via "good word" insertion | REPORTED (conference proceedings) | Origin of adversarial ML concept; criminal spam operators adopted techniques within years |
| 2014 | Neural CAPTCHA-solving demonstrated | Academic | N/A | CNN-based CAPTCHA solvers achieving ~95% accuracy | REPORTED (Usenix WoOT paper) | Established that ML could reliably bypass ML-based bot-detection at scale |
| March 2019 | **First confirmed criminal voice-cloning fraud** | Unknown criminal group | Origin unclear | AI voice synthesis cloned German CEO voice; €220,000 stolen | CONFIRMED (Euler Hermes insurer statement, PRIMARY) | Earliest verifiable documented criminal deployment of generative AI in an attack |
| January 2020 (public Oct 2021) | UAE bank voice-cloning fraud | Unknown (17 identified in UAE investigation) | Unknown | "Deep voice" AI cloned company director's voice; combined with forged emails | REPORTED (UAE court documents referenced in media, SECONDARY with primary basis) | $35M loss; tenfold scale increase over 2019 case; first cross-jurisdictional AI fraud case |
| August 2021 | Singapore GovTech GPT-3 phishing experiment | Defensive research (Singapore government) | Singapore | GPT-3-generated phishing emails outperformed human-crafted emails in click-through | REPORTED (Black Hat USA 2021 presentation) | First controlled public demonstration of LLM-generated phishing superiority |
| November 2022 | ChatGPT launches; immediate phishing volume surge | Various criminal actors | Global | LLM accessible to mass market; jailbreaks emerge within days | REPORTED (Vade Security: 274% Q3→Q4 phishing email volume increase; causal link probable but unproven) | Democratization event; LLM access no longer requires API credentials or technical sophistication |

---

### ChatGPT / Early LLM Era (2023)

| Date | Event | Actor | Country | AI Use | Evidence | Why It Matters |
|------|--------|-------|---------|--------|----------|----------------|
| July 2023 | WormGPT emerges on underground forums | "last/laste" (developer) | Unknown | GPT-J-6B-based LLM stripped of safety guardrails; marketed for BEC/phishing/malware | WEAK (underground advertisements only; Trend Micro August 2023 PRIMARY found no verified proof of functional capabilities) | Established market for criminal LLMs; actual capability much lower than advertised |
| July 22, 2023 | FraudGPT appears on dark web and Telegram | Unknown vendor | Unknown | Marketed for malware creation, phishing pages, vulnerability identification. $200/month or $1,700/year | WEAK (same caveat — Trend Micro found only promotional material, no independent verification) | Further normalized the concept of AI-as-a-service for crime |
| Q3–Q4 2023 | DPRK IT worker scheme fully documented; AI-generated fake identities confirmed | FAMOUS CHOLLIMA / Korean IT worker networks | North Korea | AI-generated photos, face-swap, enhanced deepfake IDs to pass identity verification for remote employment | CONFIRMED (DOJ indictment December 2024; FBI/CISA/State Dept advisories 2023–2024, PRIMARY) | First large-scale documented use of AI for identity fabrication to sustain long-running infiltration campaigns |
| September 2023 | MGM Resorts breach via vishing | Scattered Spider (UNC3944) | US/UK criminal network | Help-desk vishing call impersonating employee; AI voice not confirmed in 2023 attack (human social engineers used) | CONFIRMED (CISA Advisory AA23-320A, PRIMARY) | Established that sophisticated social engineering remains effective without AI; AI later adopted in Scattered Spider follow-on campaigns |
| Throughout 2023 | Nation-states experiment with LLMs | Forest Blizzard (Russia), Emerald Sleet (DPRK), Crimson Sandstorm (Iran), Charcoal Typhoon (China), Salmon Typhoon (China) | Russia, DPRK, Iran, China | Reconnaissance, scripting assistance, translation, social engineering content, code debugging | CONFIRMED (OpenAI/Microsoft joint disclosure February 14, 2024, PRIMARY) | First primary-sourced confirmation of nation-state LLM use; assessed as exploratory with no novel capability breakthrough |

---

### Nation-State Disclosure Era (2024)

| Date | Event | Actor | Country | AI Use | Evidence | Why It Matters |
|------|--------|-------|---------|--------|----------|----------------|
| January 2024 | **Arup deepfake CFO fraud — $25M loss** | Unknown criminal group | Unknown | Full multi-person real-time deepfake video conference; CFO and colleagues all AI-generated | CONFIRMED (Arup official statement + Hong Kong police, PRIMARY) | Largest documented single deepfake fraud incident; demonstrated multi-person deepfake video conference quality sufficient to deceive finance employees |
| January 24, 2024 | NCSC UK publishes landmark "Near-Term Impact of AI on Cyber Threat" | UK government | UK | N/A (assessment) | CONFIRMED (NCSC.gov.uk primary report, PRIMARY) | First major government assessment; concluded AI "almost certainly" increases cyber attack volume and impact over 2 years |
| February 14, 2024 | OpenAI + Microsoft joint disclosure of five APT groups using LLMs | OpenAI/Microsoft | USA | N/A (disclosure) | CONFIRMED (OpenAI + Microsoft Security Blog, PRIMARY) | Landmark public attribution; first primary-sourced disclosure of state-actor LLM use |
| April 2024 | UIUC paper: GPT-4 autonomously exploits 87% of one-day CVEs | Academic (University of Illinois at Urbana-Champaign) | US | GPT-4 agent exploited 87% of CVEs when given descriptions; 7% without | CONFIRMED (arXiv 2404.08144, peer-reviewed/published) | Established that LLMs have meaningful offensive vulnerability exploitation capability in controlled settings |
| May 2024 | OpenAI disrupts 5 covert influence operations | Spamouflage (China), Bad Grammar (Russia), Doppelganger (Russia), Zero Zeno (Israel), IUVM (Iran) | China, Russia, Israel, Iran | Content generation, translation, social media comment creation, code debugging for distribution bots | CONFIRMED (OpenAI primary report, PRIMARY) | None scored above 2 on Brookings Breakout Scale — AI-generated IO content failed to build real audience |
| July 30, 2024 | Singapore CSA publishes national cyber landscape report: ~13% of sampled phishing emails contained AI-generated content | N/A (government assessment) | Singapore | Quantitative sample of 40 unique phishing emails (~1% of 2023 reported attempts): 13% AI-generated content detected (detection tools caveated as imperfect) | CONFIRMED (Singapore Cyber Security Agency "Singapore Cyber Landscape 2023," PRIMARY) | One of the few official quantified measurements of AI-generated phishing content in a national dataset |
| July 2024 | KnowBe4 discloses North Korean IT worker hired with AI-generated identity | FAMOUS CHOLLIMA | North Korea | AI-generated profile photo; face-swap used on identity document | CONFIRMED (KnowBe4 company disclosure, PRIMARY) | Detailed corporate case study of DPRK AI identity fraud supply chain |
| October 2024 | OpenAI disrupts 20+ operations; names SweetSpecter, CyberAv3ngers, Storm-0817 | China (SweetSpecter), Iran (CyberAv3ngers, Storm-0817) | China, Iran | SweetSpecter: phished OpenAI employees; CyberAv3ngers: ICS/SCADA research; Storm-0817: Android malware debugging | CONFIRMED (OpenAI October 2024 report, PRIMARY) | Extended scope from IO to direct cyber operations; Iran documented as major LLM-assisted malware developer |
| October 2024 | Google Big Sleep discovers zero-day in SQLite autonomously | Google Project Zero/DeepMind | USA (defensive research) | AI agent discovered CVE-2025-6965 stack buffer underflow; reported to developers who patched same day | CONFIRMED (Google Project Zero blog, PRIMARY) | First publicly documented AI autonomous zero-day discovery in real-world production software |
| November 2024 | FinCEN deepfake alert | FinCEN | USA | N/A (advisory) | CONFIRMED (FinCEN official advisory, PRIMARY) | Federal regulator officially documented rising deepfake fraud in SARs; signals systemic threat to financial sector |
| Throughout 2024 | Iran's APT42 identified as heaviest APT user of Gemini | APT42 (IRGC-linked) | Iran | Reconnaissance, phishing lures, social engineering content, support for malware development | CONFIRMED (Google GTIG "Adversarial Misuse of Generative AI," January 2025, PRIMARY) | Largest documented state-actor AI footprint across multiple attack phases |
| Throughout 2024 | DPRK groups identified as most prolific nation-state AI users | FAMOUS CHOLLIMA / Kimsuky | North Korea | IT worker schemes: LinkedIn research, cover letters, job applications; Gmail compromise research; crypto laundering | CONFIRMED (Google GTIG January 2025, CrowdStrike GTR 2025, PRIMARY) | Operational scale and breadth; 320+ companies infiltrated with AI-assisted identity management |

---

### Inflection Point (2025)

| Date | Event | Actor | Country | AI Use | Evidence | Why It Matters |
|------|--------|-------|---------|--------|----------|----------------|
| January 2025 | Google GTIG publishes "Adversarial Misuse of Generative AI" | Various APTs | Multiple | 40+ state-sponsored APT groups using Gemini in 2024 across multiple attack phases | CONFIRMED (Google GTIG report, PRIMARY) | First comprehensive multi-actor primary assessment of APT AI use at scale |
| February 2025 | OpenAI documents romance scam networks using ChatGPT at scale | Criminal networks | Various | AI maintains multiple simultaneous victim conversations; generates persuasive scripts and fake profiles | CONFIRMED (OpenAI February 21, 2025 report, PRIMARY) | First primary-sourced documentation of criminal AI managing multiple simultaneous fraud relationships |
| H1 2025 | AI-driven vishing surges 442% (H1 to H2 2024) | Various criminal actors | Global | AI voice synthesis enables scalable vishing at reduced skill requirement | CONFIRMED (CrowdStrike GTR 2025, PRIMARY) | Statistical confirmation of scaling effect; directly linked to AI voice tool accessibility |
| June 2025 | OpenAI disrupts "ScopeCreep" malware developer and DPRK IT worker automation | Multiple (DPRK IT worker cluster; malware developer) | DPRK, other | ScopeCreep: LLM-assisted incremental development and debugging of Windows malware + C2 infrastructure. DPRK cluster: resume/persona generation, automated job-application workflows, remote-work setup research | CONFIRMED (OpenAI June 2025 threat report, PRIMARY) | First OpenAI-sourced documentation of LLM-assisted Windows malware development with named tool (ScopeCreep) |
| July–August 2025 | **GTG-2002 — Claude Code used for scaled data extortion** | GTG-2002 (Anthropic designation) | Unknown (suspected state-linked) | Claude Code used as active operator across full extortion lifecycle: vulnerability scanning, intrusion, data triage, ransom note generation, multi-victim management. 17+ organisations targeted in a single month; ransom demands >$500K. Targets include government, healthcare, emergency services, religious institutions | CONFIRMED (Anthropic August 2025 report, PRIMARY) | First Anthropic-disclosed agentic attack; distinct from GTG-1002 (this is extortion, GTG-1002 is espionage). AI managed the operational tempo of concurrent victims |
| July 17, 2025 | **LAMEHUG — first in-the-wild LLM-querying malware** | APT28 / Forest Blizzard (moderate confidence) | Russia | Python malware compiled to executable; queries Alibaba Cloud Qwen 2.5-Coder-32B-Instruct via HuggingFace API at runtime to generate Windows commands for document theft | CONFIRMED (CERT-UA advisory + Cato Networks/Picus analysis, PRIMARY) | First publicly documented malware querying an LLM during execution in live operations; genuine TTP evolution |
| November 2025 | **SesameOp — OpenAI Assistants API abused as covert C2** | Unknown espionage actor | Unknown | Backdoor (SesameOp) discovered using OpenAI Assistants API as a command-relay and data-staging channel, blending malicious C2 traffic with legitimate API calls. API key and account disabled by OpenAI on disclosure | CONFIRMED (Microsoft incident response report, November 2025, PRIMARY) | First confirmed case of a legitimate commercial AI API abused as a covert C2 relay; novel detection challenge (traffic indistinguishable from normal AI tool usage) |
| November 2025 | Anthropic disrupts GTG-1002 — agentic AI espionage campaign | GTG-1002 (Chinese state-sponsored, Anthropic designation) | China | Claude Code used for full intrusion lifecycle (recon, exploitation, credential harvesting, lateral movement, exfiltration) across ~30 targets; 80–90% AI autonomy; 4–6 human decision points/campaign. **Note: disputed by some peer analysts as overstating autonomy** — Intel 471 and Palo Alto Networks noted heavy reliance on standard open-source tools and significant hallucination | CONFIRMED (Anthropic official report November 13, 2025, PRIMARY) / **DISPUTED** on claimed autonomy degree | Strongest public claim of high-autonomy intrusion; autonomy claim plausible but contested; see §7 |
| November 2025 | PROMPTFLUX discovered — AI self-rewriting malware | Unknown | Unknown | VBScript dropper queries Gemini 1.5 Flash hourly to rewrite its own source code for evasion | CONFIRMED (Google GTIG AI Threat Tracker, PRIMARY) | First malware designed specifically for LLM-driven self-modification; experimental but documented in wild |
| November 2025 | SentinelOne retrohunt: 7,000+ malware samples with embedded AI API keys | Various (APT28-linked PROMPTSTEAL prominent) | Various | Malware embedding API keys for HuggingFace, OpenAI, Anthropic, Google to query LLMs during execution | CONFIRMED (SentinelOne LABScon 2025, PRIMARY) | Scale of LLM-querying malware ecosystem far larger than individual named samples suggest |
| December 19, 2025 | IC3 warns of AI voice-cloning campaign targeting senior US officials | Unknown actors | United States | AI-generated voice messages used to impersonate senior US officials; campaign active "since at least 2023"; targets include government-affiliated personnel and senior military contacts | CONFIRMED (FBI IC3 PSA December 19, 2025, PRIMARY) | Confirms AI voice impersonation of government officials as operational TTP since 2023; highest-profile target class yet documented in US government warning |
| 2025–2026 | GenAI exploited at 90+ organizations via malicious prompt injection | Various | Global | Prompt injection attacks against AI-integrated enterprise systems to steal credentials and cryptocurrency | CONFIRMED (CrowdStrike GTR 2026, PRIMARY) | Confirms AI integration into enterprise workflows as a new attack surface |
| March 2026 | **TeamPCP LiteLLM supply chain attack — AI infrastructure targeted** | TeamPCP (threat actor designation) | Unknown | Attackers trojanized the widely-used LiteLLM Python proxy library on PyPI by compromising maintainer accounts, inserting credential-stealing code to harvest cloud and AI API keys from downstream consumers. Estimated to affect ~36% of cloud environments | CONFIRMED (Wiz, Trend Micro, PyPI official advisories, PRIMARY) | First major confirmed attack targeting AI routing infrastructure itself — not using AI offensively, but treating AI supply chain as the attack surface. Signals a new threat category |

---

## 4. Major Incidents

### 4.1 UK Energy Company CEO Voice Cloning Fraud
**Date:** March 2019
**Actor:** Unknown criminal group
**Victim:** UK-based energy company (German parent company CEO voice cloned)
**AI Component:** Text-to-speech AI software cloned the German CEO's voice, including his accent and speech patterns. Three calls were made: first to demand €220,000 transfer to a "Hungarian supplier within the hour"; second to falsely claim reimbursement; third attempt to extract additional funds (refused when victim became suspicious of Austrian mobile number).
**Loss:** €220,000 (~$243,000 USD) — fully transferred, not recovered
**Insurance:** Euler Hermes covered the claim and described it as "the first cybercrime they'd heard of using AI."
**Source:** PRIMARY (Euler Hermes insurer statement; reported Wall Street Journal, September 2019)
**Novel vs. Standard TTP:** Novel — no prior confirmed criminal use of AI voice synthesis. The attack template (CEO impersonation, urgent wire transfer) is standard BEC; the AI component was genuinely new.
**Why It Matters:** Establishes 2019 as the start of the AI fraud timeline. All subsequent voice fraud incidents build on this template.

---

### 4.2 UAE Bank Voice Cloning Fraud — $35 Million
**Date:** January 2020 (publicly disclosed October 2021)
**Actor:** Unknown (at least 17 individuals identified in UAE investigation)
**Victim:** Hong Kong-based bank manager of a Japanese company
**AI Component:** "Deep voice" AI technology cloned a company director's voice. Combined with forged emails, the system authorized fund transfers across multiple accounts. UAE police formally requested US judicial assistance to trace $400,000 reaching US Centennial Bank accounts.
**Loss:** $35 million USD
**Source:** REPORTED (UAE court documents referenced in media; SECONDARY with primary document basis)
**Novel vs. Standard TTP:** Voice AI was the novel component. The fraud mechanics (wire transfer authorization via impersonation) are standard social engineering. The scale ($35M vs $220K in 2019) indicates a 143x increase in a single incident.
**Why It Matters:** First major-scale voice AI fraud; demonstrated cross-jurisdictional criminal sophistication and near-state-level coordination.

---

### 4.3 Arup Deepfake CFO Fraud — $25 Million
**Date:** Early January 2024 (Arup confirmed publicly May 2024)
**Actor:** Unknown criminal group
**Victim:** Arup plc (British multinational engineering firm); finance employee in Hong Kong office
**AI Component:** Real-time multi-person deepfake video conference. An employee received a request appearing to come from the UK CFO, was initially suspicious, but was invited to a video call featuring deepfake recreations of the CFO and multiple Arup colleagues — all AI-generated simultaneously. Following instructions from the call, the employee made 15 wire transfers totaling HKD$200 million.
**Loss:** HKD$200 million (~$25.6 million USD) to five Hong Kong bank accounts
**Discovery:** Employee contacted real headquarters afterward; fraud detected. No internal systems compromised.
**Source:** PRIMARY (Arup official statement + Hong Kong police confirmation; CNN, Fortune, CFO Dive)
**Novel vs. Standard TTP:** Multi-person real-time deepfake video conference is genuinely novel. This is a qualitative step beyond audio-only voice cloning; visual corroboration significantly reduces victim skepticism.
**Sectors:** Professional services (engineering), financial operations
**Why It Matters:** Largest documented single deepfake fraud incident. Demonstrates that multi-person video deepfakes are deployable against corporate finance processes.

---

### 4.4 North Korean IT Worker Scheme — FAMOUS CHOLLIMA
**Date:** Ongoing 2021–present; fully documented by FBI/DOJ 2023–2024; KnowBe4 case July 2024
**Actor:** FAMOUS CHOLLIMA (CrowdStrike designation); multiple DPRK-linked networks
**Scale:** 320+ companies infiltrated; 80+ US persons' identities compromised; 100+ US companies victimized (DOJ December 2024 indictment)
**AI Component:** AI-generated profile photos for fake LinkedIn/job site identities; face-swap and deepfake technology on identity documents to bypass KYC verification; AI potentially used to manage simultaneous "employment" at multiple firms; ChatGPT/Gemini used for LinkedIn research, cover letter generation, job application optimization.
**Loss:** Revenue generated from salaries; in some cases, data theft and malware deployment following infiltration
**Source:** CONFIRMED PRIMARY (DOJ indictment December 2024; FBI/CISA/State Dept advisories 2023–2024; KnowBe4 company disclosure July 2024; Google GTIG January 2025)
**Novel vs. Standard TTP:** Using AI to fabricate employment identities at industrial scale is novel. DPRK has been doing identity fraud for years, but AI-generated photos and face-swap technology enabling passing of automated KYC systems is a qualitative change.
**Why It Matters:** Demonstrates that AI enables sustained, long-term organizational infiltration. Unlike a one-time fraud event, this is continuous revenue generation with insider access.

---

### 4.5 OpenAI/Microsoft APT Disclosure — February 2024
**Date:** February 14, 2024
**Actor:** Forest Blizzard (GRU/Russia), Emerald Sleet (Kimsuky/DPRK), Crimson Sandstorm (IRGC/Iran), Charcoal Typhoon (China), Salmon Typhoon (China)
**AI Component:** See actor segmentation (Section 8). Summary: open-source research, scripting, translation, social engineering content, code debugging. All five groups had accounts terminated.
**Source:** CONFIRMED PRIMARY (OpenAI + Microsoft Security Blog joint disclosure)
**Novel vs. Standard TTP:** Not novel in attack category — all uses mapped to existing pre-AI TTPs. Novelty is in scale, speed, and language capability of AI assistance.
**Why It Matters:** First primary-sourced public attribution of state-actor LLM use. Established that all major threat nation-states were experimenting with LLMs simultaneously.

---

### 4.6 APT42 AI-Enabled Operations — 2024
**Date:** Throughout 2024
**Actor:** APT42 (IRGC-linked, Iran)
**AI Component:** Heaviest documented state-actor use of Gemini across reconnaissance, phishing lure generation, social engineering content, support for malware development. Multiple attack phases covered.
**Source:** CONFIRMED PRIMARY (Google GTIG "Adversarial Misuse of Generative AI," January 2025)
**Notable Sub-Case:** Crimson Sandstorm (related Iranian cluster) generated spear-phishing emails including one impersonating an international development agency and one targeting feminist activists (OpenAI February 2024 disclosure).
**Why It Matters:** Iran, not Russia or China, is the state actor with the widest documented AI adoption across the attack lifecycle. This contradicts assumptions that the most capable cyber powers are necessarily the most AI-forward.

---

### 4.7 LAMEHUG — First In-the-Wild LLM-Querying Malware
**Date:** July 17, 2025 (CERT-UA advisory)
**Actor:** APT28 / Forest Blizzard (MODERATE CONFIDENCE, CERT-UA attribution)
**Victim:** Ukraine (government entities; distributed via phishing impersonating Ukrainian ministry officials)
**AI Component:** Python malware (compiled to .pif executable via PyInstaller) that at runtime queries Alibaba Cloud's Qwen 2.5-Coder-32B-Instruct model via the HuggingFace inference API. The LLM dynamically generates Windows system commands for the malware to execute — used for document discovery and exfiltration.
**Technical detail:** SentinelOne identified 284 unique HuggingFace API keys embedded across LAMEHUG/PROMPTSTEAL samples (keys sourced from a 2023 credential dump).
**Source:** CONFIRMED PRIMARY (CERT-UA advisory July 2025; Cato Networks, Picus Security independent analyses; Google GTIG AI Threat Tracker, November 2025)
**Novel vs. Standard TTP:** Genuinely novel. Prior malware uses static logic or downloads staged payloads. LAMEHUG uses a live LLM to generate commands at execution time — the malware's behavior is partially determined by an external AI model, making static analysis insufficient for full detection.
**Why It Matters:** Represents a documented paradigm shift: from AI-assisted development of malware (offline) to AI-integrated malware execution (online). Detection requires understanding of LLM API traffic patterns in addition to traditional IOCs.

---

### 4.8 GTG-1002 — First Documented Agentic AI Intrusion Campaign
**Date:** Discovered September 2025; reported November 13, 2025
**Actor:** GTG-1002 (Anthropic internal designation; Chinese state-sponsored attribution)
**Scope:** ~30 global targets across technology firms, financial institutions, chemical manufacturers, and government bodies
**AI Component:** Claude Code (Anthropic's agentic coding assistant) used to conduct the full intrusion lifecycle: reconnaissance, exploitation, credential harvesting, lateral movement, data exfiltration. AI performed 80–90% of intrusion processes autonomously. Human operators intervened at 4–6 decision points per campaign.
**Limitation noted:** Claude hallucinated during operations — occasionally overstated findings, misidentified public information as secret, or fabricated data in reports to operators.
**Source:** CONFIRMED PRIMARY (Anthropic official report, November 13, 2025)
**Novel vs. Standard TTP:** Novel in degree of autonomy applied to the full intrusion lifecycle. All constituent TTPs (recon, exploitation, lateral movement) existed pre-AI; what's new is an AI agent orchestrating them with minimal human direction.
**Why It Matters:** First primary-sourced case of AI autonomously conducting cyber espionage at operational scale. Shifts the threat model: defenders must now consider that an intrusion may be executed predominantly by an AI system, not a human operator.

---

### 4.9 GTG-2002 — Claude Code as Data Extortion Operator
**Date:** July–August 2025 (Anthropic report August 2025)
**Actor:** GTG-2002 (Anthropic internal designation; attribution unclear at publication)
**Scope:** 17+ organisations targeted in a single month: government agencies, healthcare providers, emergency services, religious institutions
**AI Component:** Claude Code used as an active autonomous operator across the full extortion lifecycle — vulnerability scanning, initial access, data discovery and triage, exfiltration, ransom note generation, and multi-victim negotiation management. The AI simultaneously managed multiple active victim engagements.
**Ransom demands:** Reported at >$500,000 per victim in some cases
**Source:** CONFIRMED PRIMARY (Anthropic August 2025 threat report)
**Note:** GTG-2002 is a separate disclosed case from GTG-1002 (espionage, November 2025). GTG-2002 is financially motivated extortion; GTG-1002 is state espionage. Both involve agentic AI but with different objectives.
**Novel vs. Standard TTP:** Genuine novelty in the AI orchestrating concurrent multi-victim extortion campaigns — the "operational tempo" and parallelism are only achievable via AI automation.
**Why It Matters:** Extends agentic AI from espionage (GTG-1002) into the criminal extortion ecosystem. AI as an autonomous operator in ransomware-adjacent workflows is the highest-maturity criminal agentic AI case documented through April 2026.

---

### 4.10 SesameOp — Legitimate AI API as Covert C2
**Date:** Discovered July 2025; disclosed November 2025
**Actor:** Unknown espionage actor (unattributed)
**AI Component:** A backdoor (designated SesameOp) used the OpenAI Assistants API as a covert command-and-control relay and data-staging channel. Malicious C2 traffic was indistinguishable from legitimate AI tool usage, making network-based detection extremely difficult. Commands were issued through the AI service; output was staged there. OpenAI terminated the account and API key upon disclosure by Microsoft's incident response team.
**Source:** CONFIRMED PRIMARY (Microsoft incident response report, November 2025)
**Novel vs. Standard TTP:** Genuinely novel attack surface. Prior C2 channels abused cloud services (Google Drive, Dropbox, Slack webhooks). Abusing an AI API as C2 is new: the traffic is HTTPS to a widely-trusted commercial endpoint, has legitimate user-agent patterns, and the protocol (Assistants API) provides built-in persistence and message threading.
**Why It Matters:** SesameOp demonstrates that as AI APIs become standard enterprise egress traffic, they create a blind spot for security teams who cannot easily distinguish malicious from legitimate AI API calls. Detection requires behavioral analysis of API usage patterns, not just allowlist-based filtering.

---

### 4.11 TeamPCP / LiteLLM Supply Chain Attack
**Date:** March 2026
**Actor:** TeamPCP (threat actor designation by Wiz/Trend Micro)
**Victim:** Enterprise AI developers and SaaS providers using LiteLLM (a widely-used Python library that routes requests between enterprise applications and multiple LLM providers)
**AI Component (none — the target was AI infrastructure):** Attackers compromised PyPI maintainer accounts for LiteLLM and inserted credential-harvesting code that silently exfiltrated cloud API keys, AI provider tokens, and system prompts from any application importing the package. Estimated scope: ~36% of cloud environments globally.
**What was stolen:** Cloud provider credentials (AWS, GCP, Azure); AI API keys (OpenAI, Anthropic, Cohere, others); internal system prompts (often containing sensitive business logic).
**Source:** CONFIRMED PRIMARY (Wiz, Trend Micro research; PyPI official advisory, March 2026)
**Novel vs. Standard TTP:** Supply chain compromise via PyPI is not novel (see XZ Utils 2024, SolarWinds 2020). What is novel is the target: AI middleware. Stealing AI API credentials provides downstream access to enterprise AI contexts, system prompts (often proprietary), and all data those AI systems process.
**Why It Matters:** Establishes a new threat category: the AI supply chain. Attackers do not need to use AI offensively if they can steal the credentials that power an enterprise's AI — then they have access to everything the AI accesses, and can potentially manipulate AI system behavior by injecting content into the prompt context.

---

### 4.12 ScopeCreep — LLM-Assisted Malware Development
**Date:** June 2025 (OpenAI disruption report)
**Actor:** Unknown malware developer (accounts disrupted by OpenAI)
**AI Component:** Actor used OpenAI models to iteratively develop and debug a Windows malware payload — incrementally improving code quality, fixing syntax errors, adding evasion features, and troubleshooting C2 infrastructure configuration. The development process showed clear evidence of AI co-piloting: queries included specific error messages, stack traces, and requests to "make this code undetectable by Windows Defender."
**Source:** CONFIRMED PRIMARY (OpenAI June 2025 threat intelligence report)
**Novel vs. Standard TTP:** Malware development with LLM co-pilot assistance is not new as a concept (documented since OpenAI's February 2024 disclosure) but ScopeCreep is notable as the most detailed named case of incremental LLM-assisted Windows malware engineering with documented AI interaction patterns.
**Why It Matters:** Demonstrates that LLM assistance reduces malware development cycle time and lowers the expertise required. AI does not replace the developer but significantly reduces the time-per-iteration on debugging and evasion improvement.

---

### 4.13 PROMPTFLUX — Self-Rewriting AI Malware
**Date:** November 2025
**Actor:** Unknown (unattributed at publication)
**AI Component:** VBScript dropper that queries the Gemini 1.5 Flash API hourly to rewrite its own source code, specifically targeting signature-based detection evasion. Each iteration is functionally equivalent but syntactically different.
**Assessment:** Described by Google as experimental/testing phase. "Lacks any means to independently compromise a victim network or device" at the point of detection. Not yet weaponized.
**Source:** CONFIRMED PRIMARY (Google GTIG AI Threat Tracker, November 2025)
**Why It Matters:** Even in testing phase, demonstrates that LLM-driven automated evasion is being actively developed. A weaponized version would challenge signature-based AV/EDR products.

---

## 5. TTP Analysis (ATT&CK-Aligned)

> For each TTP: status (Confirmed / Reported / Theoretical), examples, current limitations.

---

### TA0043 — Reconnaissance

**AI Usage:** LLM-assisted OSINT, target profiling, social media research, translation of foreign-language sources.

**Status: CONFIRMED** (OpenAI/Microsoft February 2024; Google GTIG January 2025)

- Forest Blizzard used ChatGPT to research satellite communication protocols and radar imaging technology.
- Emerald Sleet used ChatGPT to research think tanks and experts on North Korean defense policy.
- Salmon Typhoon translated technical papers and researched intelligence agencies.
- APT42 used Gemini for target profiling ahead of phishing campaigns.
- SweetSpecter (China) used ChatGPT to research publicly known vulnerabilities before targeting OpenAI employees.

**Limitations:** AI provides breadth and speed in OSINT; it does not access non-public data. LLMs cannot perform network scanning or probe internal systems independently. LLMs also hallucinate — they generate plausible-sounding but false information, which can mislead attackers (confirmed in GTG-1002 case).

---

### TA0042 — Resource Development

**AI Usage:** Generating spear-phishing lure content; developing fake identities for social media, employment, and infiltration; building malware scaffolding; automating account creation.

**Status: CONFIRMED** (multiple primary sources)

- FAMOUS CHOLLIMA used AI-generated photos, face-swap on ID documents, and LLM-generated cover letters/LinkedIn profiles for IT worker infiltrations.
- Crimson Sandstorm used ChatGPT to generate spear-phishing emails impersonating an international development agency.
- WormGPT/FraudGPT marketed for BEC template generation (effectiveness unverified per Trend Micro, but market exists).
- KnowBe4 disclosed that a North Korean operative used an AI-generated photo to pass automated identity verification.

**Limitations:** AI-generated content retains detectable artifacts; AI-generated images may fail liveness detection in KYC flows with advanced anti-fraud tooling. AI-generated identities fail when subjected to human investigation of deep profile history.

---

### TA0001 — Initial Access

**AI Usage:** AI-enhanced phishing (language quality, personalization); AI-generated voice for vishing/help desk attacks; deepfake video for fraud authorization.

**Status: CONFIRMED** (multiple primary sources)

- Vishing: CrowdStrike documented 442% increase H1→H2 2024, explicitly attributed to AI voice synthesis accessibility.
- Deepfake CFO fraud: Arup ($25M); UAE bank ($35M); 2019 CEO fraud ($243K).
- Phishing text generation: Crimson Sandstorm, APT42, Emerald Sleet confirmed.
- Help desk social engineering: Scattered Spider (2023) used human operators; follow-on campaigns reportedly adopted AI voice agents.
- Quantified effectiveness: AI-generated phishing emails achieved 54% click-through vs. 12% for human-written control (SECONDARY; multiple vendor citations, methodology varies).

**Limitations:** AI voice cloning quality degrades under scrutiny; verification call-backs and out-of-band confirmation disrupt attacks. AI phishing at volume risks triggering automated volume-based detection.

---

### TA0011 — Command and Control

**AI Usage:** LLM APIs queried during malware execution to dynamically generate commands; legitimate AI services abused as covert C2 relay channels; AI-generated communication patterns for traffic-blending evasion.

**Status: CONFIRMED** — two distinct confirmed patterns as of April 2026:

**Pattern A — LLM-as-brain (runtime command generation):**
- LAMEHUG (July 2025): Python malware queries Qwen 2.5-Coder at runtime; static C2 logic replaced by dynamic LLM-generated Windows commands.
- PROMPTFLUX (November 2025): Queries Gemini hourly — the LLM functions as an external evasion service.

**Pattern B — Legitimate AI API as C2 relay:**
- SesameOp (November 2025, Microsoft, PRIMARY): Backdoor used OpenAI Assistants API as command relay and data-staging channel. C2 traffic was legitimate HTTPS to api.openai.com — indistinguishable from normal AI tool usage on a network level. API key terminated on disclosure.
- SesameOp represents a higher-impact pattern than Pattern A: no custom infrastructure required; traffic blends into enterprise AI egress; detection requires behavioral profiling of AI API usage, not IP/domain blocklists.

**Limitations:** Pattern A — requires outbound HTTPS to AI provider APIs; detectable via egress analysis; API key revocation degrades ongoing campaigns. Pattern B — requires maintaining a valid AI provider account; account termination breaks C2; detection possible via anomalous API usage patterns (volume, threading, unusual payload structures).

---

### TA0002 — Execution (Malware Development)

**AI Usage:** LLM-assisted scripting, debugging, code generation; AI queried during malware execution to generate payloads or system commands.

**Status: CONFIRMED** (multiple primary sources)

- Storm-0817 (Iran) used ChatGPT to debug Android malware (OpenAI October 2024, PRIMARY).
- APT41 used Gemini for tool development and code translation (Google GTIG January 2025, PRIMARY).
- APT42 used Gemini for malware development support (Google GTIG January 2025, PRIMARY).
- LAMEHUG: LLM queried at execution time for dynamic command generation (CERT-UA July 2025, PRIMARY).
- MalTerminal (~late 2023): GPT-4 API used to generate ransomware/reverse shell code on demand (PoC, no confirmed wild deployment).

**Limitations:** LLMs produce functional but generic code; bespoke, sophisticated malware still requires skilled human developers. LLM code generation does not replace zero-day research.

---

### TA0043/T1566 — Social Engineering / Phishing

**AI Usage:** Grammar improvement, personalization, multilingual translation, voice/video deepfakes for authorization fraud, romance scam script generation, influence operation content.

**Status: CONFIRMED — highest maturity of any AI-enabled TTP**

- OpenAI disrupted romance scam networks using ChatGPT to manage multiple simultaneous victim conversations (February 2025, PRIMARY).
- AI generates convincing phishing emails in 5 minutes vs. 16 hours for human red team with comparable click-through rates (Hoxhunt, SECONDARY).
- Doppelganger (Russia) used AI to translate and generate influence content in 6+ languages at scale impossible without AI.
- AI vs. human red team: AI surpassed human red team effectiveness by February–March 2025 (Hoxhunt, SECONDARY).

**Limitations:** Personalized AI phishing at volume can trigger volume-based detection. AI cannot reliably tailor attacks based on real-time conversational cues without human oversight or agentic design.

---

### TA0005 — Defense Evasion

**AI Usage:** AI-generated code variants for signature evasion; automated obfuscation; LLM-driven code rewriting; adversarial ML evasion of endpoint AI detectors.

**Status: CONFIRMED (early stage)**

- PROMPTFLUX: Queries Gemini hourly to rewrite VBScript dropper for signature evasion (Google GTIG, November 2025, PRIMARY).
- Adversarial ML evasion of spam/phishing classifiers: documented academically since 2004; criminal adoption assumed but not primary-sourced.
- NCSC (January 2024): "Realistic possibility that highly capable states have repositories of malware large enough to effectively train an AI model" for systematic evasion.

**Limitations:** LLM-driven evasion introduces API latency and communication overhead; detectable via behavioral analysis rather than signature-based detection. Behaviorally anomalous LLM API egress traffic creates new detection opportunity.

---

### TA0006 — Credential Access

**AI Usage:** AI-improved password spraying targeting patterns; deepfake-enabled MFA bypass (voice/video verification); AI-generated targeted credential stuffing lists.

**Status: REPORTED** (limited primary sourcing on the AI component specifically)

- CyberAv3ngers (IRGC) used ChatGPT to research common default credentials for ICS PLCs (OpenAI October 2024, PRIMARY). This is targeting research, not direct credential theft.
- FAMOUS CHOLLIMA used AI-generated identities to pass identity verification in employment contexts — adjacent to credential access in the identity fraud sense.
- Mass password attacks have scaled (Microsoft: 600M+ daily attempts in 2024) but the AI contribution to spray pattern optimization is not separately primary-sourced.

**Limitations:** Most credential theft (phishing, infostealer malware, credential dumps) does not require AI to be effective. AI provides marginal optimization, not fundamental capability change.

---

### TA0040 — Impact (Extortion / Ransomware)

**AI Usage:** Claimed for negotiation automation, target profiling, data analysis; NOT confirmed for core ransomware encryption/deployment operations.

**Status: THEORETICAL / NOT CONFIRMED FOR RANSOMWARE**

- No primary CTI source (Microsoft, CrowdStrike, Mandiant, Palo Alto) confirms AI adoption in core LockBit, CL0P, or equivalent ransomware operational TTPs.
- NCSC (January 2024): "AI will likely contribute to the global ransomware threat in the near term" — this is a forward-looking probability assessment, not a documented current finding.
- AI could theoretically accelerate triage of exfiltrated data to identify the most valuable files for double-extortion leverage. No confirmed cases.

**Limitations:** Ransomware groups are primarily defined by their affiliate and RaaS model efficiency, not technical sophistication. AI integration would need to show clear ROI advantage over existing affiliate networks.

---

### TA0009 — Collection (Data Analysis / Exfiltration Support)

**AI Usage:** AI-assisted triage and analysis of exfiltrated data to identify high-value targets for monetization; translation of foreign-language documents.

**Status: REPORTED** (NCSC assessment; no confirmed named-actor primary sourcing)

- NCSC (January 2024, PRIMARY): "AI will almost certainly make cyber attacks against the UK more impactful because threat actors will be able to analyse exfiltrated data faster."
- GTG-1002 (Anthropic November 2025): AI conducted data exfiltration as part of agentic campaign — though details of post-collection processing not disclosed.

---

### AI Supply Chain — Emerging TTP Category (2026+)

**AI Usage:** Compromising the open-source libraries, proxy servers, and API middleware that connect enterprises to LLMs — stealing AI API credentials, system prompts, and intercepting AI-processed data.

**Status: CONFIRMED (first confirmed case March 2026)**

- TeamPCP / LiteLLM (March 2026, PRIMARY): Trojanized PyPI library harvesting AI API keys and system prompts at scale (~36% of cloud environments estimated). No AI used offensively — the AI infrastructure itself is the target.
- QUIETVAULT (GTIG, 2025): Credential stealer using embedded AI prompts and on-host AI CLI tools to autonomously search for developer secrets (GitHub tokens, NPM keys, API credentials) on compromised hosts. Bridges traditional credential theft with AI-aware targeting.

**Why this is a new category:** Traditional supply chain attacks target software dependencies. AI supply chain attacks target the trust layer between enterprise applications and AI providers. Stolen AI API keys provide: (a) access to all data the enterprise feeds to the AI; (b) ability to manipulate AI system behavior by injecting context; (c) impersonation of the enterprise's AI footprint. This is structurally different from credential theft targeting user accounts.

**Limitations:** Requires supply chain position (PyPI, npm, container registry). Detection possible via dependency pinning, cryptographic hash verification, and CI/CD integrity monitoring.

---

### IO / Influence Operations

**AI Usage:** Synthetic content generation (text, image, video) at scale; multilingual translation; automated social media engagement; synthetic persona management.

**Status: CONFIRMED — widely documented, with important caveat on impact**

- All five IO operations disrupted by OpenAI (May 2024) and 20+ subsequently (October 2024) used AI for content generation.
- Key impact finding: None scored above 2 on Brookings' Breakout Scale. No viral audience was built via AI-generated IO content through 2024.
- Iran: First documented use of AI-generated video for influence operation — April 2024 (Microsoft DDR 2024, PRIMARY), ahead of a military operation.
- Europol (2025): AI enables "multilingual victim targeting" across influence operations.

**Limitations:** AI-generated content remains detectable via metadata, watermarking, and behavioral anomaly patterns. Building authentic-seeming audiences requires human seeding that AI alone cannot replicate. Volume without engagement is not influence.

---

## 6. Statistics and Measurable Trends

> Methodology note: Statistics vary significantly by vendor, measurement methodology, and sample population. Where figures conflict or have weak sourcing, this is noted explicitly.

---

### 6.1 Attack Volume

| Metric | Figure | Source | Source Quality |
|--------|--------|--------|----------------|
| Daily password attacks against Microsoft customers (2024) | 600 million+ | Microsoft DDR 2024 | PRIMARY |
| Daily password attacks against cloud identities (Q1 2023 surge) | 3B → 30B/month (tenfold) | Microsoft DDR 2023 | PRIMARY |
| Human-operated ransomware incidents increase (2024) | 2.75x year-over-year | Microsoft DDR 2024 | PRIMARY |
| Phishing attack volume Q3→Q4 2022 (post-ChatGPT launch) | 274% increase (74.4M → 278.3M emails) | Vade Security Q4 2022 | SECONDARY (causal link unproven) |
| Phishing surge linked to GenAI since 2023 | 1,265% | SlashNext | WEAK (single vendor, methodology unclear) |
| Vishing increase H1→H2 2024 | 442% | CrowdStrike GTR 2025 | PRIMARY |
| Voice phishing as share of initial infection vectors (2025 investigations) | 11% of initial vectors (up from lower baseline); email phishing dropped to 6% | Mandiant M-Trends 2026 | PRIMARY |
| DPRK IT worker infiltrations year-over-year increase | 220% | CrowdStrike GTR 2025 | PRIMARY |
| Companies compromised by FAMOUS CHOLLIMA | 320+ | CrowdStrike GTR 2025 | PRIMARY |
| Fake account creation attempts blocked per hour (Apr 2024–Apr 2025) | 1.6 million | Microsoft DDR 2025 | PRIMARY |
| AI-generated IDs growth globally (Microsoft telemetry) | 195% | Microsoft DDR 2025 | PRIMARY |
| Fraud schemes blocked by Microsoft in one year (Apr 2024–Apr 2025) | $4 billion | Microsoft DDR 2025 | PRIMARY |

---

### 6.2 Phishing Effectiveness

| Metric | Figure | Source | Quality |
|--------|--------|--------|---------|
| AI-generated phishing click-through rate | 54% | Multiple vendor citations (Hoxhunt); supported by peer-reviewed arXiv study (101 participants) | SECONDARY (methodology varies across citations) |
| Fully AI-automated phishing click-through (controlled study) | 54% (matching skilled human experts at 54%); AI with minimal human-in-loop: 56% | Peer-reviewed arXiv study (101 participants) | SECONDARY (academic, human subjects) |
| Control/baseline phishing click-through (same study) | 12% | Same arXiv study | SECONDARY (academic) |
| Fraction of recipients falling for AI phishing | 60% | Harvard research | SECONDARY (academic) |
| AI phishing campaign generation time | 5 minutes | Hoxhunt | SECONDARY |
| Human red team phishing campaign generation time | 16 hours | Hoxhunt | SECONDARY |
| AI surpassing human red team in phishing | Feb–Mar 2025 | Hoxhunt | SECONDARY |
| Portion of national phishing sample containing AI-generated content | ~13% of 40 sampled phishing emails (~1% of 2023 reported attempts) | Singapore CSA "Singapore Cyber Landscape 2023," July 2024 | PRIMARY (with caveat: detection tools imperfect, small sample) |

*Note: The arXiv controlled study (101 participants) is the strongest methodology available for phishing effectiveness comparisons. The 54% figure is robust across multiple citations. Treat the 1,265% surge figure (SlashNext) with skepticism — single vendor, unclear methodology.*

---

### 6.3 Deepfake Fraud

| Metric | Figure | Source | Quality |
|--------|--------|--------|---------|
| Documented deepfake incidents increase (2024) | 257% (to 150 documented) | Pindrop | SECONDARY |
| Deepfake activity increase (Pindrop method) | 680% year-over-year | Pindrop | SECONDARY |
| Projected US AI-facilitated fraud losses (2023) | $12.3 billion | Deloitte | SECONDARY |
| Projected US AI-facilitated fraud losses (2027) | $40 billion (32% CAGR) | Deloitte | SECONDARY |
| Average per-incident deepfake business loss (2024) | ~$500,000 | Vendor figure | WEAK (aggregate, methodology varies) |
| FBI IC3 total internet crime losses 2024 | $16.6 billion (33% increase) | FBI IC3 2024 | PRIMARY |
| BEC losses 2024 | $2.77 billion | FBI IC3 2024 | PRIMARY |

*Note: FBI IC3 does not disaggregate AI/deepfake fraud as a separate category. Deepfake losses are embedded within BEC, investment fraud, and romance scam categories.*

---

### 6.4 Underground Forum Trends

| Metric | Figure | Source | Quality |
|--------|--------|--------|---------|
| Increase in dark web mentions of malicious AI tools (2024) | 219% | KELA Intelligence | SECONDARY |
| Rise in AI jailbreak discussions (2024) | 52% | KELA Intelligence | SECONDARY |
| ChatGPT jailbreak offers on dark web (2023) | 249 | Vendor research | SECONDARY |
| ChatGPT mention vs. other AI models in criminal forums | 550% more | CrowdStrike GTR 2026 | PRIMARY |

---

### 6.5 Attack Speed

| Metric | Figure | Source | Quality |
|--------|--------|--------|---------|
| eCrime average breakout time (2025) | 29 minutes | CrowdStrike GTR 2026 | PRIMARY |
| Fastest recorded eCrime breakout | 27 seconds | CrowdStrike GTR 2026 | PRIMARY |
| Mean time to exfiltrate (2021) | 9 days | Palo Alto Unit 42 | PRIMARY |
| Mean time to exfiltrate (2024) | 2 days | Palo Alto Unit 42 | PRIMARY |

*These speed improvements are partly attributable to automation and living-off-the-land techniques; AI contribution is not disaggregated.*

---

### 6.5b FBI IC3 2025 — AI-Specific Crime Statistics (First Available)

The FBI's 2025 IC3 annual report (covering calendar year 2025) is the first to include a dedicated AI-linked complaints category — the most authoritative quantitative baseline currently available for AI-enabled cyber-enabled crime in the United States.

| Metric | Figure | Source | Quality |
|--------|--------|--------|---------|
| Total complaints with AI-related information (2025) | 22,364 | FBI IC3 Annual Report 2025 | PRIMARY |
| Total adjusted losses (AI-related complaints, 2025) | $893,346,472 (~$893M) | FBI IC3 Annual Report 2025 | PRIMARY |
| Investment scams with AI nexus (losses) | $632 million | FBI IC3 Annual Report 2025 | PRIMARY |
| BEC with AI nexus (losses) | $30.3 million | FBI IC3 Annual Report 2025 | PRIMARY |
| Other AI-linked categories | Tech support, romance scams, personal data breach, employment, phishing/spoofing | FBI IC3 Annual Report 2025 | PRIMARY |

**Important caveat from the IC3 report itself:** These figures are likely a significant undercount. Victims may not recognise AI involvement — especially in investment scams where overall losses exceed $8 billion. The $632M AI-linked investment scam figure represents AI-recognised cases only.

**Structural note:** AI-linked losses are concentrated in investment fraud ($632M out of $893M) — not BEC ($30M). This is counterintuitive relative to media narratives but consistent with the broader finding that AI's biggest criminal impact is on fraud targeting individuals (investment scams, romance scams) rather than corporate BEC at the reported scale.

---

### 6.6 LLM-Integrated Malware Scale

| Metric | Figure | Source | Quality |
|--------|--------|--------|---------|
| Malware samples with embedded AI API keys (VirusTotal retrohunt) | 7,000+ | SentinelOne LABScon 2025 | PRIMARY |
| Unique AI API keys found across malware samples | 6,000+ | SentinelOne LABScon 2025 | PRIMARY |
| Unique HuggingFace API keys in APT28/PROMPTSTEAL samples | 284 | SentinelOne LABScon 2025 | PRIMARY |
| Named AI API providers found in malware | OpenAI, HuggingFace, Anthropic, Google, others | SentinelOne LABScon 2025 | PRIMARY |

---

## 7. Reality vs. Hype

### 7.1 What AI Is Genuinely Changing in Offensive Operations

**Confirmed real impacts (high confidence):**

1. **Social engineering quality and scale.** AI eliminates the grammar/spelling/translation tells that historically identified phishing and scams. Multilingual campaigns that required specialized human operators can now be run at scale. Romance scam networks maintain dozens of victim conversations simultaneously. This is measurable and primary-sourced.

2. **Voice and video impersonation quality.** The 2019→2020→2024 progression from voice-only to multi-person real-time video deepfakes represents a genuine capability trajectory. 30 seconds of target audio is sufficient for convincing voice clone. This directly challenges call-back verification procedures and verbal authorization processes.

3. **Speed of content production.** Phishing campaigns generated in 5 minutes vs. 16 hours; multilingual IO content generated at scale; code assistance reducing LLM-assisted scripting time. AI is a genuine force multiplier for activities that were previously bottlenecked by human writing/translation/coding time.

4. **Barrier to entry reduction.** Less-skilled actors can now conduct attacks that previously required specialized technical or linguistic expertise. Europol, NCSC, and NCA all confirm this in primary reports.

5. **LLM-integrated malware (2025).** LAMEHUG and PROMPTFLUX demonstrate that AI integration into malware execution is operationally real, not theoretical. The scale (7,000+ malware samples with embedded API keys) suggests broader ecosystem development beyond named samples.

6. **Agentic AI intrusion (late 2025).** GTG-1002 represents a genuine paradigm shift in what AI can do operationally. Even if agentic intrusion remains rare, the model is proven.

---

### 7.2 What Is Mostly Marketing, Panic, or Speculation

**Claims that do not hold up to primary evidence:**

1. **Criminal dark LLMs (WormGPT, FraudGPT) as capable tools.** Trend Micro's August 2023 PRIMARY analysis found zero verified proof that WormGPT or FraudGPT worked as advertised. The developer shut down WormGPT mid-2023 due to "negative publicity." The real risk was never bespoke criminal LLMs — it was jailbroken access to legitimate models.

2. **AI-powered ransomware.** Despite widespread vendor claims, no primary CTI report confirms AI integration into LockBit, CL0P, or any major ransomware group's core operational TTPs. The ransomware ecosystem runs on affiliate models, zero-day exploitation, and credential theft — not AI. This may change but is not currently documented.

3. **"Fully autonomous AI hacking" in the wild.** The UIUC paper (GPT-4 exploiting 87% of CVEs) and Google Big Sleep zero-day are research-environment demonstrations. The GTG-1002 case (2025) involved 80–90% AI autonomy but still required human decision points. NCSC's 2025 assessment: "Fully automated, end-to-end advanced cyberattacks is unlikely before 2027."

4. **The 1,265% phishing surge.** This SlashNext figure is a single-vendor claim with unclear methodology. It should not be cited as authoritative without independent verification. The post-ChatGPT phishing volume increase is real (multiple sources confirm it) but the magnitude of this specific claim is unverified.

5. **AI-generated influence operations building real audiences.** OpenAI's May 2024 disclosure showed that AI dramatically lowered content production costs but did not help IO actors build genuine engagement. None of five major operations scored above 2 on Brookings' Breakout Scale. AI-generated content at scale is not the same as AI-generated persuasion at scale.

---

### 7.3 New TTPs vs. Improved Old TTPs

**Verdict: Primarily enhancement of existing TTPs, with three genuine novelties in 2025.**

- **2019–2024 period:** All documented AI-enabled attacks were improvements of existing attack categories. Voice cloning enhances CEO fraud (existing TTP). LLM phishing improves spear phishing (existing TTP). AI-generated IO content accelerates influence operations (existing TTP). No new attack categories created.

- **Consensus:** NCSC (2024), OpenAI (2024), IBM X-Force (2024), Mandiant (2025): AI enhances existing TTPs rather than creating novel attack vectors. "We haven't seen evidence of threat actors creating novel malware or meaningful breakthroughs" (OpenAI October 2024).

- **2025 exceptions that represent genuine novelty:**
  - **LAMEHUG:** Malware querying an LLM at runtime is a new TTP — not an enhancement of existing remote access tool design.
  - **PROMPTFLUX:** AI-driven hourly self-rewriting for signature evasion has no direct pre-AI analog.
  - **Agentic intrusion (GTG-1002):** AI autonomously orchestrating full kill chain is a new operational model, not an enhancement of human-operated intrusion.

---

### 7.4 Autonomous Hacking — Research vs. Reality

| Setting | Finding | Status |
|---------|---------|--------|
| UIUC (April 2024): GPT-4 exploits 87% of CVEs with description, sandboxed | Autonomous vulnerability exploitation proven in controlled environment | Research (no real victims) |
| Google Big Sleep (October 2024): Zero-day in SQLite discovered autonomously | First AI autonomous zero-day discovery in production software | Defensive research (no malicious deployment) |
| Unit 42 red team: AI simulates full ransomware kill chain in 25 minutes | AI can execute full attack in test environment | Red team exercise |
| GTG-1002 (November 2025): 80–90% autonomous intrusion across ~30 targets | Anthropic claims first real-world agentic intrusion confirmed; **disputed by peer analysts** | CONFIRMED (Anthropic primary) / DISPUTED on autonomy degree |
| GTG-2002 (August 2025): Claude Code as extortion operator at 17 organisations | Corroborating agentic AI extortion case from same provider | CONFIRMED (Anthropic primary) |

**Key limitation on GTG-1002:** Anthropic's November 2025 report is a primary source and the strongest public claim of high-autonomy intrusion. However, Intel 471 and Palo Alto Networks analysts independently reviewed the case and noted: AI frequently hallucinated, generated bug-ridden exploit code, and ultimately relied heavily on standard open-source penetration testing tools deployed and supervised by human operators. The "80–90% AI autonomy" figure is Anthropic's own assessment from a provider perspective; independent corroboration of the autonomy fraction is limited.

**The correct analytical position:** High-autonomy agentic intrusion is real and documented. The specific fraction of automation is disputed. "Largely autonomous" rather than "fully autonomous" is the defensible characterisation with current evidence.

### 7.5 The "AI Ransomware" Panic — A Case Study in Hype

In late 2025, reports circulated about **PROMPTLOCK** — widely described as the "first AI-powered ransomware in the wild." In reality, PROMPTLOCK was an academic proof-of-concept developed by researchers at NYU Tandon to simulate how a local LLM could autonomously identify files and generate encryption scripts. It was uploaded to VirusTotal for standard academic testing, where several AV vendors flagged it as malicious — triggering media coverage of an "AI ransomware" that never existed as an active threat.

**The PROMPTLOCK case illustrates:** (a) Security researchers publish AI-enabled attack PoCs; these are frequently misidentified as in-the-wild threats. (b) Real ransomware operators continue to use proven, mathematically sound encryption algorithms (AES, RSA) rather than trusting an LLM to handle encryption. (c) LLM-generated code for encryption is slower, less reliable, and more detectable than optimised purpose-built cryptographic implementations. PROMPTLOCK demonstrates technical feasibility but tells us nothing about actual criminal adoption.

**Contrast with real AI malware:** LAMEHUG and PROMPTFLUX are confirmed in-the-wild. The distinction: LAMEHUG uses the LLM for *command generation* (not encryption); PROMPTFLUX uses the LLM for *code rewriting for evasion* (not encryption). Neither uses AI for the cryptographic core. AI is being used in the parts of malware where its probabilistic output is acceptable (generating commands, obfuscating code); not in parts where cryptographic precision is required (encryption/decryption).

---

## 8. Actor Segmentation

### 8.1 Financially Motivated Cybercrime (BEC / Fraud)

**AI Adoption Level: HIGH — most advanced of any category**

BEC and fraud actors were the first criminal adopters of AI (voice cloning, 2019) and remain the most mature. The use cases are tightly aligned with AI's actual strengths: natural language generation, voice/video synthesis, identity fabrication.

- Voice cloning: Deployed at scale since 2019; first $35M+ loss documented 2020.
- Deepfake video: Operationally deployed by 2024 (Arup case).
- Romance scam automation: ChatGPT managing multiple simultaneous victim conversations (OpenAI 2025).
- BEC template generation: Established market via WormGPT/FraudGPT ecosystem even if specific tools were vaporware — jailbroken legitimate LLMs fill the gap.

**Why ahead:** Fraud benefits directly from AI's language and synthesis capabilities. Measurable ROI is immediate (transfer executed or not). No sophisticated infrastructure required beyond a phone/video call.

---

### 8.2 Ransomware Operators

**AI Adoption Level: LOW — no confirmed operational integration**

Despite widespread vendor speculation, no primary CTI source documents AI integration into core ransomware TTPs. Ransomware operations are defined by their RaaS affiliate ecosystems, zero-day acquisition, and initial access broker relationships — areas where AI provides marginal advantage.

**Most likely near-term AI use cases for ransomware:**
- AI-assisted triage of exfiltrated data to identify highest-leverage files for double extortion.
- AI-generated negotiation communications.
- AI-enhanced phishing for initial access (via affiliates).

**Why behind:** Ransomware's core value is reliable encryption and an established payment/negotiation infrastructure. AI doesn't improve these. Affiliates operate on known toolsets (Cobalt Strike, commercial RATs) with established playbooks.

---

### 8.3 Nation-State / APT Groups

**AI Adoption Level: MEDIUM to HIGH — varies significantly by country**

**Iran (APT42, Charcoal/Mint Sandstorm, CyberAv3ngers): HIGHEST** — Google GTIG identified APT42 as the single heaviest state-actor Gemini user across the broadest attack phases. Uses AI for reconnaissance, phishing, malware development support, ICS research. Most mature state adoption documented.

**North Korea (FAMOUS CHOLLIMA, Kimsuky/Emerald Sleet): HIGH** — Most prolific in breadth of use cases. AI enables identity fraud at scale (IT worker schemes), cryptocurrency research, spear-phishing. 320+ companies infiltrated; 220% year-over-year growth.

**China (APT41, Charcoal Typhoon, Salmon Typhoon, GTG-1002): MEDIUM-HIGH** — AI used for tool development, code translation, real-time troubleshooting (APT41); translation and research (Salmon Typhoon); and agentic intrusion (GTG-1002). Strategically capable but documented as "exploratory" in 2023; more operationally deployed in 2025.

**Russia (APT28/Forest Blizzard, Doppelganger, Bad Grammar): MEDIUM** — Primarily deployed for influence operations (IO content at scale, translation). LAMEHUG (APT28, 2025) represents a shift to operational malware integration. Relative under-utilization compared to Iran and DPRK is surprising given GRU's technical reputation.

**Why differences exist:** Iran's IRGC-linked groups have a high operational tempo in social engineering and must operate efficiently with limited technical resources — AI aligns with their existing TTP preferences. DPRK has a clear financial mandate (cryptocurrency, IT worker revenue) that aligns perfectly with AI-enabled identity fraud. Russia has capable human operators who may perceive less marginal AI benefit; IO operations are a natural fit.

---

### 8.4 Influence / IO Actors

**AI Adoption Level: HIGH for content production; LOW for actual audience impact**

AI dramatically lowered IO content production costs. Spamouflage, Doppelganger, Bad Grammar, IUVM, and Zero Zeno all confirmed as AI content generators. However, the critical finding is that this production advantage did not translate to audience impact: no operation scored above 2 on Brookings' Breakout Scale through 2024.

**Why behind on impact:** Authentic influence requires trust networks built over time. AI can generate text but cannot build the social credibility needed for viral engagement. Coordinated inauthentic behavior detection has kept pace with AI content generation quality improvements.

---

### 8.5 Hacktivists

**AI Adoption Level: LOW to MEDIUM**

NCSC noted that AI lowers barriers for hacktivists. Documented evidence is limited to AI-enhanced defacement, AI-generated messaging, and AI-assisted DDoS coordination. No primary-sourced hacktivist AI intrusion case documented.

**Why behind:** Hacktivist goals (disruption, messaging) are achievable with off-the-shelf tools without AI integration. AI provides marginal tactical improvement; organizational capacity and target selection matter more.

---

## 9. Technical Evolution

### Stage 1: Adversarial ML and CAPTCHA Bypass (2004–2018)
Early exploitation of AI against AI: ML spam filters evaded by ML-generated content (2004). Neural CAPTCHA solvers achieving ~95% accuracy by 2014. Commercial CAPTCHA-solving services mainstream by 2017–2020. This stage is largely invisible in current threat reporting but established the template: use AI to defeat AI-based defenses.

---

### Stage 2: Generative Voice Synthesis in Fraud (2019–2022)
First criminal deployment: UK CEO voice cloning, March 2019 (€220K). UAE bank, January 2020 ($35M). Voice cloning crosses from research toy to operational criminal tool. Commercial platforms (ElevenLabs, Resemble AI) make high-quality synthesis accessible without ML expertise. This stage established voice impersonation as a viable criminal TTP and preceded LLM availability.

---

### Stage 3: LLM Democratization and Criminal Exploration (Nov 2022 – Dec 2023)
ChatGPT launches. Dark web forum discussion of jailbreaking begins within days. Underground "criminal LLM" products (WormGPT, FraudGPT) emerge but are largely vaporware. Nation-states experiment with LLM access throughout 2023. DPRK IT worker schemes begin using AI-generated identities. The capability is real; the criminal applications are mostly social engineering, identity fabrication, and content generation. No confirmed AI-assisted intrusion or malware development in this stage.

---

### Stage 4: Nation-State Disclosure and Influence Operations (2024)
OpenAI/Microsoft joint disclosure (February 2024) confirms five state actors using LLMs. OpenAI disrupts 20+ IO operations using AI content. Arup deepfake CFO fraud ($25M) demonstrates that multi-person real-time video deepfakes are operationally deployable. CyberAv3ngers uses ChatGPT to research ICS vulnerability exploitation. Storm-0817 uses AI to debug Android malware. The pattern: widespread adoption across reconnaissance, social engineering, and content generation; limited confirmed adoption in intrusion TTPs. All major AI providers publicly commit to monitoring and disrupting state-actor LLM abuse.

---

### Stage 5: LLM-Integrated Malware and Agentic Intrusion (2025)
Three primary-sourced developments mark a genuine phase transition:
- **LAMEHUG** (July 2025): malware queries LLM at runtime — the first in-the-wild shift from "AI helps develop malware" to "AI is part of malware execution."
- **GTG-1002** (November 2025): AI autonomously executes 80–90% of intrusion lifecycle — first real-world agentic cyber espionage.
- **PROMPTFLUX** (November 2025): malware designed to rewrite itself via AI API — first designed-for-AI-evasion malware in the wild.

SentinelOne's retrohunt finding of 7,000+ malware samples with embedded AI API keys suggests the named samples are the visible tip of a broader ecosystem.

---

### Stage 5: Legitimate AI Services as Attack Infrastructure (2025–2026)
SesameOp (November 2025) introduces a distinct fifth stage: attackers abusing legitimate commercial AI APIs as covert C2 channels. Unlike LAMEHUG (which built its own API access to a third-party model), SesameOp exploited a commercial AI provider's legitimate API endpoints for C2 — blending malicious traffic into normal enterprise AI API egress. The TeamPCP/LiteLLM attack (March 2026) extends this: rather than abusing AI APIs, attackers targeted the middleware connecting enterprises to those APIs, stealing the entire AI credential and context layer. These two patterns define Stage 5: AI infrastructure (APIs, proxy libraries, model registries) as the attack surface, not just AI as the attack tool.

---

### Stage 6: Likely Next Stage (2026–2028)
Based on current trajectory:
- **AI-native malware frameworks:** Malware designed from the ground up to leverage LLM APIs for dynamic behavior generation, not as a bolt-on feature.
- **Multi-model orchestration:** Attack chains using different AI models for different phases (one LLM for recon, another for payload generation, another for C2 instruction generation).
- **Agentic attacks at scale:** Multiple simultaneous AI-agent intrusion campaigns managed by a small human team — the GTG-1002 model applied at wider breadth.
- **AI-driven vulnerability discovery at scale:** Transition from Big Sleep (Google defensive research) to offensive application — AI systematically scanning public code repositories and binary patches for exploitable bugs.
- **Deepfake authentication bypass:** AI-generated real-time biometric bypass against facial recognition and voice authentication systems used in banking and access control.

---

## 10. Forecast

### 10.1 12-Month Forecast (to April 2027)

**Most likely developments:**

1. **AI supply chain attacks become a primary threat vector.** The TeamPCP/LiteLLM case is the proof-of-concept. As enterprise AI adoption grows (every major application now integrates AI APIs), the libraries and proxy layers connecting enterprises to LLMs become high-value targets. Expect repeated supply chain compromises of PyPI/npm AI packages; expect AI API key harvesting to become a standard post-exploitation step alongside traditional credential theft. Defenders who have not inventoried their AI dependencies and pinned package versions are highly exposed.

2. **LLM-querying malware goes mainstream.** The LAMEHUG/PROMPTSTEAL model will be adopted by additional threat actors beyond APT28. Expect to see criminal groups (not just nation-states) deploying malware with embedded AI API calls. Detection tooling will lag adoption by 6–12 months.

2. **Deepfake video fraud scales significantly.** The technical barrier for multi-person real-time deepfake video (the Arup attack vector) continues to fall. Expect this attack to move from isolated high-value corporate targets to broader financial sector deployment. Average deal size will likely decrease as tooling becomes more accessible.

3. **AI-enhanced vishing as default criminal TTP.** The 442% vishing increase documented in 2024 will continue. Voice cloning will become standard equipment for BEC actors and call-center fraud operations, not a specialized capability.

4. **Agentic intrusion adoption by additional state actors.** GTG-1002 demonstrated the model. Other Chinese clusters and potentially DPRK/Iranian groups will attempt to replicate or acquire similar agentic tooling. Expect 2–4 additional primary-sourced agentic intrusion cases in this period.

5. **Prompt injection against AI-integrated enterprise systems.** CrowdStrike documented 90+ organizations compromised via malicious prompt injection in 2025. This attack surface will expand in proportion to enterprise AI adoption.

**High-risk use cases:**
- Financial sector: deepfake-enabled wire transfer authorization bypass
- Healthcare: AI-generated patient records / insurance fraud
- Government: AI-assisted identity fraud for security clearance applications

**Highest-confidence near-term escalation:** AI voice cloning in BEC (HIGH), LLM-querying malware adoption (HIGH), prompt injection against enterprise AI (MEDIUM).

---

### 10.2 3-Year Forecast (to 2029)

**Most likely trajectory:**

1. **AI-driven vulnerability discovery becomes offensive.** The Google Big Sleep model (autonomous zero-day discovery) will be applied offensively. Well-resourced state actors (China, Russia, DPRK) will run AI systems against public code repositories and binary patches to identify exploitable vulnerabilities before vendors issue patches. This represents the highest-risk AI capability shift in this timeframe.

2. **Automated intrusion campaigns at scale.** Human-to-AI ratio in intrusion operations continues to decrease. A small team of 3–5 operators orchestrating dozens of simultaneous AI-agent intrusion campaigns becomes plausible. Current constraints (LLM hallucination, human oversight requirements) will partially resolve with model improvements.

3. **Deepfake-enabled biometric authentication bypass.** Real-time AI bypass of facial recognition and voice authentication used in banking KYC and access control. FinCEN's 2024 alert on deepfake fraud in financial institutions marks the beginning of this threat arc; by 2029, it will be a standard attack vector.

4. **Criminal AI tool ecosystem matures.** Unlike 2023's largely vaporware underground LLMs, the 2027–2028 period will see functional criminal AI tooling — built on open-source model fine-tuning and uncensored model hosting, not on misleading advertisements.

5. **AI for ICS/OT targeting.** CyberAv3ngers' 2024 ICS/SCADA research using ChatGPT is the early signal. By 2028, AI-assisted analysis of operational technology vulnerabilities will be a documented TTP for state-linked actors with ICS targeting mandates.

**What defenders are underestimating:**
- The speed at which agentic AI intrusion will scale once the model is proven.
- The authentication threat from deepfakes — current enterprise MFA and call-back procedures assume real-time voice is trustworthy.
- The shift from AI-developed malware to AI-executed malware — detection logic designed for the former will not catch the latter.

---

### 10.3 5-Year Forecast (to 2031)

**Plausible but uncertain developments:**

1. **Near-fully autonomous AI-driven intrusion campaigns.** By 2031, AI systems may conduct end-to-end intrusion campaigns with 1–2 human decision points (target selection, weaponization authorization) rather than 4–6. The GTG-1002 model will have matured significantly.

2. **AI-enabled zero-day markets.** AI-discovered vulnerabilities become a commercial product. State-sponsored offensive research organizations use AI to systematically discover and stockpile zero-days at rates previously impossible. This will structurally favor offense over defense.

3. **AI-generated malware families undetectable by signature.** PROMPTFLUX represents an early iteration. By 2031, malware capable of continuous AI-driven self-modification will challenge signature-based detection to the point of obsolescence for non-AI-native detection systems.

4. **Deepfake-as-a-service for large-scale fraud.** Real-time deepfake generation becomes a commoditized criminal service — pay per fraud attempt, with AI-generated personas maintained across multiple sessions.

**What is unlikely despite hype:**
- A single catastrophic "AI cyberattack" that brings down critical infrastructure autonomously. Real-world critical infrastructure attacks require ICS-specific knowledge, physical-cyber convergence understanding, and careful operational planning that pure AI automation does not yet provide.
- Criminal ransomware groups fully automating their core encryption and negotiation operations. The human judgment in target selection, negotiation, and payment processing has proven resistant to automation.

**Early warning indicators to watch:**
- AI provider API traffic anomalies in enterprise egress (monitoring for LAMEHUG-model malware at scale)
- Darknet evidence of functional open-source fine-tuned models for offensive tasks (not vaporware)
- Google/Anthropic/OpenAI threat intelligence reports disclosing additional agentic intrusion cases
- FinCEN SAR filing trends for deepfake-related fraud (next aggregate data point expected 2025–2026)
- Security vendor reports of AI-discovered zero-days in offensive campaigns

---

## 11. Final Conclusions

**Five conclusions supported by the weight of primary evidence:**

**1. 2025 is the genuine inflection point.** Prior years saw AI enhancing existing TTPs. 2025 produced the first primary-sourced in-the-wild LLM-querying malware, first AI-driven self-rewriting malware, and first agentic intrusion campaign. The threat model changed qualitatively, not just quantitatively.

**2. Social engineering and fraud remain the highest-impact AI use cases.** Not because intrusion use cases are unimportant, but because the earliest, most consistent, highest-dollar-loss applications of AI in attacks are in fraud and social engineering. The Arup case ($25M) and UAE bank case ($35M) dwarf any documented AI-assisted intrusion impact. Organizations investing AI threat budgets in intrusion detection while underinvesting in fraud controls and call verification procedures are misallocating resources.

**3. AI lowers barriers more than it creates superweapons.** The dominant effect of AI adoption by attackers is scale and accessibility — more actors doing existing attacks more efficiently — not the creation of capabilities that didn't exist before. The scale effect is dangerous in aggregate (higher phishing volume, more vishing operators, broader IO coverage) even when individual AI-enabled attacks are not qualitatively more sophisticated.

**4. LLM hallucination is an attacker constraint, not just a defender worry.** GTG-1002 demonstrated that AI agents make mistakes during live operations — they fabricate findings, misidentify data, and require human correction. This buys defenders time but does not make AI-driven attacks benign.

**5. The detection gap is real and widening.** Organizations designed to detect human-operated intrusions will struggle against agentic AI intrusions. Organizations using signature-based detection will fail against PROMPTFLUX-model self-rewriting malware. Organizations relying on voice call-back verification will fail against real-time voice deepfakes. Detection infrastructure built for the pre-AI threat model requires re-examination against the 2025 threat model.

---

## 12. Top 10 Milestones Table

| # | Date | Milestone | Evidence Quality |
|---|------|-----------|-----------------|
| 1 | March 2019 | First confirmed criminal AI voice cloning attack (UK CEO fraud, €220K) | PRIMARY |
| 2 | January 2020 | First large-scale AI voice cloning fraud ($35M, UAE bank) | SECONDARY (court basis) |
| 3 | November 2022 | ChatGPT launch — LLM democratization; jailbreaking starts within days | Structural event |
| 4 | July 2023 | WormGPT/FraudGPT emergence — underground AI market established (capabilities unverified) | WEAK (claims only) |
| 5 | February 14, 2024 | OpenAI/Microsoft joint disclosure: five nation-state APTs confirmed using LLMs | PRIMARY |
| 6 | January 2024 | Arup CFO deepfake fraud ($25M) — multi-person real-time video deepfake deployed | PRIMARY |
| 7 | July 2025 | LAMEHUG confirmed in wild — first malware querying LLM at execution time (APT28) | PRIMARY |
| 8 | August 2025 | GTG-2002 — Claude Code as autonomous extortion operator at 17 organisations | PRIMARY |
| 9 | November 2025 | SesameOp — first legitimate AI API (OpenAI Assistants) abused as covert C2 relay | PRIMARY |
| 10 | March 2026 | TeamPCP/LiteLLM — first major AI supply chain attack; ~36% of cloud environments affected | PRIMARY |

---

## 13. Top 10 Incidents Table

| # | Date | Incident | Loss / Impact | AI Component | Sector | Source |
|---|------|----------|--------------|-------------|--------|--------|
| 1 | Jan 2024 | Arup CFO deepfake fraud | $25.6M | Multi-person real-time deepfake video conference | Professional services | PRIMARY |
| 2 | Jan 2020 | UAE bank voice cloning fraud | $35M | Voice cloning of company director | Financial | SECONDARY (court basis) |
| 3 | Mar 2026 | TeamPCP / LiteLLM supply chain attack | ~36% of cloud environments; API credentials, system prompts stolen | AI supply chain compromise (no AI used offensively) | Enterprise SaaS, AI developers | PRIMARY |
| 4 | Jul–Aug 2025 | GTG-2002 agentic data extortion (17 orgs) | Ransom demands >$500K per victim; government, healthcare, emergency services targets | Claude Code as autonomous extortion operator | Government, healthcare, emergency | PRIMARY (Anthropic) |
| 5 | 2021–2024 | FAMOUS CHOLLIMA IT worker scheme | 320+ companies infiltrated; millions in fraudulent wages + insider access | AI-generated identities, face-swap, deepfake ID documents | Technology, government | PRIMARY (DOJ, FBI) |
| 6 | Jul 2025 | LAMEHUG malware campaign (APT28) | Espionage; Ukraine government targets | LLM-querying malware generating system commands at runtime | Government / Ukraine | PRIMARY (CERT-UA) |
| 7 | Nov 2025 | GTG-1002 agentic espionage (~30 targets) | Espionage across tech, finance, government | Full intrusion lifecycle; 80–90% AI autonomy (disputed) | Technology, finance, government | PRIMARY (Anthropic) |
| 8 | Nov 2025 | SesameOp (AI API as covert C2) | Espionage persistence; scope undisclosed | OpenAI Assistants API abused as command relay | Single environment (public) | PRIMARY (Microsoft) |
| 9 | 2024 | APT42 AI-enabled operations (Iran) | Espionage | AI across full attack lifecycle: recon, phishing, malware development | Multiple sectors | PRIMARY (Google GTIG) |
| 10 | Mar 2019 | UK energy company CEO fraud | $243K | AI voice synthesis of German CEO | Energy | PRIMARY (insurer) |

---

## 14. Defender Recommendations

Based on the documented threat landscape, organized by priority:

**Immediate (within 90 days):**

1. **Implement out-of-band verification for all financial wire transfers and authorization requests received via voice or video.** A callback to a pre-registered number using a separate channel is the single most effective control against deepfake CEO/CFO fraud. Voice and video confirmation is no longer sufficient as a sole authorization mechanism.

2. **Audit your organization's AI API egress traffic patterns.** LLM-querying malware (LAMEHUG model) generates HTTPS traffic to AI provider APIs. Establish a baseline of legitimate AI API usage and alert on anomalous outbound calls to HuggingFace, OpenAI, Anthropic, Google AI, and Alibaba Cloud AI endpoints. Unauthorized API calls from endpoints are a high-confidence IOC.

3. **Run a phishing simulation using AI-generated content.** Test whether your organization's current phishing training prepares employees to recognize AI-generated content — which lacks traditional grammar/spelling signals. Update training if click-through rates exceed organizational benchmarks.

4. **Update identity verification procedures for remote workers and vendors.** AI-generated photos and face-swap technology defeat static image-based KYC. Implement liveness detection and multi-step verification. Cross-reference with government identity databases where available.

**Medium-term (3–12 months):**

5. **Deploy AI-native detection tooling.** Signature-based AV/EDR will not detect PROMPTFLUX-model malware. Behavioral detection, network traffic analysis, and anomaly-based approaches are required. Evaluate vendors specifically on their capability against LLM-querying and self-modifying malware.

6. **Map your attack surface for agentic AI exposure.** If your organization uses AI code assistants, agentic AI platforms, or API-connected AI services, assess whether an attacker could abuse these (via prompt injection, stolen API keys, or compromised AI-adjacent systems) to gain access or escalate privileges.

7. **Review your MFA infrastructure against real-time deepfake bypass.** Voice-based MFA and video-based identity verification are increasingly vulnerable. Hardware security keys (FIDO2) and other phishing-resistant MFA forms are not susceptible to voice/video deepfake attacks and should be prioritized.

8. **Monitor underground AI tool markets and AI provider threat intelligence disclosures.** OpenAI, Google GTIG, Anthropic, and Microsoft regularly publish threat intelligence reports on state-actor and criminal AI abuse. Align threat intelligence feed coverage to include these disclosures.

**Medium-term (3–12 months):**

7. **Audit and pin all AI-related dependencies.** The TeamPCP/LiteLLM case demonstrates that AI proxy libraries are high-value supply chain targets. Pin all AI-related Python/npm packages to exact versions using cryptographic hashes in lockfiles. Disable automatic mutable version updates for AI middleware. Treat AI dependencies (LiteLLM, LangChain, LlamaIndex, etc.) with the same supply chain scrutiny as security-critical libraries.

8. **Inventory AI API credentials as privileged secrets.** AI API keys grant access to everything your enterprise sends to an AI provider — including sensitive business data and system prompts containing proprietary logic. Store AI API keys in secrets managers (not hardcoded, not in environment files). Rotate regularly. Monitor for credential exfiltration via SIEM rules covering API key patterns in egress data.

**Strategic (12+ months):**

9. **Assume agentic AI intrusion as part of your threat model.** Design detection strategies that account for intrusion campaigns conducted predominantly by AI agents — not by human operators following predictable human behavioral patterns. AI-driven intrusions may move faster, operate at unusual hours, and generate traffic patterns inconsistent with human operation.

10. **Develop AI-specific incident response procedures.** A SOC designed to analyze human-operated intrusions needs adaptation for AI-operated ones. Key differences: AI agents may generate higher-volume, lower-dwell-time lateral movement; AI hallucination may produce unusual artifacts (fabricated log entries, overstated access claims); AI-generated phishing and social engineering require different victim communication and training responses.

11. **Engage with AI provider abuse reporting mechanisms.** OpenAI, Anthropic, and Google all operate threat intelligence programs and accept reports of suspected malicious AI usage. If you identify LLM API calls in malware or suspect an AI system is being used against your organization, these providers have disruption capabilities (account termination, key invalidation) that can degrade ongoing campaigns.

---

## 15. Source Register

| Source | Type | Quality | Key Findings Used |
|--------|------|---------|------------------|
| OpenAI/Microsoft "Disrupting Malicious Uses of AI by State-Affiliated Threat Actors" (Feb 14, 2024) | Joint official disclosure | PRIMARY | Five APT groups using LLMs; assessed as exploratory |
| OpenAI "Disrupting Deceptive Uses of AI by Covert Influence Operations" (May 30, 2024) | Official report | PRIMARY | Five IO operations disrupted; none built real audience |
| OpenAI "Influence and Cyber Operations: An Update" (October 9, 2024) | Official report | PRIMARY | 20+ operations disrupted; SweetSpecter, CyberAv3ngers, Storm-0817 |
| OpenAI Threat Intelligence Report (February 21, 2025) | Official report | PRIMARY | Romance scam networks; Chinese IO targeting Japan |
| Microsoft Digital Defense Report 2023 (October 2023) | Official report | PRIMARY | AI for phishing, IO; attack volume statistics |
| Microsoft Digital Defense Report 2024 (October 2024) | Official report | PRIMARY | 600M daily password attacks; AI IO use by Iran |
| NCSC UK "Near-Term Impact of AI on Cyber Threat" (January 24, 2024) | Government assessment | PRIMARY | "Almost certainly" increases attack volume; barrier to entry |
| NCSC UK "Impact of AI on Cyber Threat to 2027" (2025) | Government assessment | PRIMARY | Enhancement not novel TTPs; full autonomy unlikely before 2027 |
| Google GTIG "Adversarial Misuse of Generative AI" (January 2025) | Vendor primary research | PRIMARY | 40+ APTs on Gemini; APT42 heaviest user; DPRK most prolific |
| Google GTIG AI Threat Tracker (November 2025) | Vendor primary research | PRIMARY | LAMEHUG, PROMPTFLUX, PROMPTSTEAL; 5+ in-wild LLM malware families |
| Google Project Zero "Big Sleep" blog (October 2024) | Primary research blog | PRIMARY | First autonomous AI zero-day in production software |
| CERT-UA Advisory (July 17, 2025) | Government advisory | PRIMARY | LAMEHUG attribution to APT28; Qwen API querying |
| Anthropic Report on GTG-1002 (November 13, 2025) | Company official report | PRIMARY | First agentic AI intrusion; 80–90% autonomy; 30 targets |
| CrowdStrike Global Threat Report 2025 | Vendor primary report | PRIMARY | 442% vishing increase; FAMOUS CHOLLIMA; phishing stats |
| CrowdStrike Global Threat Report 2026 | Vendor primary report | PRIMARY | 89% increase AI-enabled adversaries; prompt injection at 90+ orgs |
| FBI IC3 2024 Internet Crime Report | Government primary | PRIMARY | $16.6B total losses; BEC $2.77B; crypto $9.3B |
| FinCEN Deepfake Fraud Alert (November 2024) | Government advisory | PRIMARY | SAR increase for deepfake fraud since 2023 |
| CISA Advisory AA23-320A (Scattered Spider, November 2023) | Government advisory | PRIMARY | MGM breach; vishing methodology |
| DOJ DPRK IT Worker Indictment (December 2024) | Court/legal document | PRIMARY | 80+ identities; 100+ companies; AI-generated profiles |
| KnowBe4 DPRK worker disclosure (July 2024) | Company disclosure | PRIMARY | AI photo; face-swap ID; detailed supply chain |
| Euler Hermes statement on 2019 CEO fraud | Insurer primary witness | PRIMARY | First confirmed criminal voice cloning; €220K |
| Arup official statement + Hong Kong Police (May 2024) | Company + government | PRIMARY | $25M deepfake CFO fraud; 15 transfers; video deepfake |
| Trend Micro "Hype vs. Reality" (August 2023) | Vendor primary research | PRIMARY | WormGPT/FraudGPT capabilities NOT verified |
| SentinelOne LABScon 2025 presentation | Vendor primary research | PRIMARY | 7,000+ malware samples; 6,000+ AI API keys; PROMPTSTEAL |
| IBM X-Force Threat Intelligence Index 2024 | Vendor primary report | PRIMARY | No concrete evidence of GenAI-engineered attacks in 2023–2024 |
| Europol EU-SOCTA 2025 | Government/agency | PRIMARY | AI "fundamentally reshaping organized crime" |
| UIUC autonomous hacking paper (April 2024, arXiv 2404.08144) | Academic | SECONDARY | 87% CVE exploitation rate with description; 7% without |
| UAE $35M voice cloning (2021 public disclosure) | Court documents via media | SECONDARY | $35M loss; 17 identified individuals |
| Vade Security Q4 2022 phishing report | Vendor quarterly | SECONDARY | 274% Q3→Q4 phishing surge post-ChatGPT launch |
| Hoxhunt phishing effectiveness research | Vendor research | SECONDARY | 54% vs 12% click-through; AI surpassed humans Feb 2025 |
| KELA Intelligence underground forum data | Vendor research | SECONDARY | 219% dark web AI tool mentions; 52% jailbreak discussions |
| SlashNext 1,265% phishing surge | Single vendor claim | WEAK | Cited for context only; methodology unclear |
| WormGPT/FraudGPT marketing claims | Underground advertisements | WEAK | No functional capability independently verified |
| OpenAI June 2025 threat report (ScopeCreep, DPRK IT workers) | Official report | PRIMARY | ScopeCreep LLM-assisted malware dev; DPRK job automation at scale |
| Anthropic August 2025 report (GTG-2002) | Official report | PRIMARY | Agentic extortion; Claude Code as operator; 17 orgs in one month |
| Microsoft IR report, November 2025 (SesameOp) | Primary vendor IR | PRIMARY | OpenAI Assistants API abused as covert C2/relay |
| Wiz + Trend Micro + PyPI advisory (TeamPCP / LiteLLM, March 2026) | Vendor + registry primary | PRIMARY | AI supply chain attack; ~36% cloud environment exposure |
| Mandiant M-Trends 2026 | Primary vendor report | PRIMARY | Voice phishing 11% of initial vectors; email phishing declined to 6% |
| Microsoft Digital Defense Report 2025 | Official report | PRIMARY | $4B fraud blocked/yr; 1.6M fake accounts/hr; AI-ID growth 195% |
| FBI IC3 Annual Report 2025 | Government primary | PRIMARY | 22,364 AI complaints; $893M adjusted losses; $632M investment scams |
| FBI IC3 PSA December 19, 2025 | Government advisory | PRIMARY | AI voice cloning of senior US officials since at least 2023 |
| Singapore CSA "Singapore Cyber Landscape 2023" (July 30, 2024) | Government primary | PRIMARY | ~13% of phishing sample AI-generated (small sample, caveated) |
| Peer-reviewed arXiv phishing study (101 participants, controlled) | Academic peer-reviewed | SECONDARY | AI-automated phishing achieves 54% click-through matching human experts |

---

*Evidence cutoff: April 2026. All citations reference publicly available documents as of this date. Classification: Open source / Unclassified.*

*For corrections, additional sourcing, or technical questions: [Medium @1200km](https://medium.com/@1200km)*
