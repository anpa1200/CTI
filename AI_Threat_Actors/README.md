# AI in Offensive Operations: How Threat Actors Use Artificial Intelligence

**A rigorous, evidence-based CTI report on the evolution of AI usage by cybercriminal groups, ransomware operators, fraud actors, and state-linked APTs — from the earliest documented cases through April 2026.**

By [Andrey Pautov](https://medium.com/@1200km) — April 2026

> **v7 — Updated April 2026.** Evidence cutoff: April 2026. v7 restructures the Executive Summary to lead with the 2025–2026 threat picture; collapses Stages 5/5b/6 into a single integrated-operations section; trims the Actor Segmentation section (Sandworm/Handala sub-sections consolidated); renames §9.1 to "Historical Precursors"; cuts the 5-year forecast; adds SIEM specifics to Defender Recommendations; converts TTP narrative paragraphs to references; and applies additional confidence/tone calibrations throughout.

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

**The current threat picture, as of late 2025 through early 2026, is defined by five confirmed, primary-sourced developments that represent genuine TTP evolution rather than incremental productivity gains:**
1. **LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG)** (July 2025) — first in-the-wild malware querying an LLM during execution (APT28-attributed). Assessed as exploratory/pilot phase by MITRE and Cato Networks researchers.
2. **PROMPTFLUX** (discovered early June 2025; publicly disclosed November 4–5, 2025, Google GTIG) — first documented malware family in testing phase designed for LLM-driven just-in-time code regeneration for signature evasion. Self-modification function was commented out in analyzed samples; GTIG assesses it as currently in development phase.
3. **GTG-1002** (November 2025, Anthropic) — AI agent reported to conduct 80–90% of an intrusion lifecycle across ~30 targets. **(Sole disclosure: Anthropic. Peer analysts — Intel 471, Palo Alto Networks — dispute the stated autonomy degree. See §7.4.)**
4. **SesameOp** (November 2025, Microsoft) — first confirmed abuse of a legitimate AI API (OpenAI Assistants) as a covert C2/relay channel.
5. **GTG-2002** (August 2025, Anthropic) — Claude Code used as active operator in data extortion targeting 17 organisations including government and healthcare. **(Sole disclosure: Anthropic.)**

**2026 data indicates the emergence of AI infrastructure targeting as a distinct threat category.** The March 2026 TeamPCP/LiteLLM attack — trojanizing a dominant AI proxy library on PyPI — demonstrates that the infrastructure connecting enterprises to LLMs is itself a target, separate from AI being used offensively.

The trajectory that produced these developments: March 2019 represents the earliest primary-sourced criminal AI case in this review (UK CEO voice cloning, €220K, Euler Hermes insurer). The pre-ChatGPT period (2019–2022) was dominated by isolated voice-cloning and deepfake fraud. ChatGPT's November 2022 launch changed accessibility but did not immediately produce AI-powered intrusions — the February 2024 OpenAI/Microsoft disclosure confirmed five nation-state groups using LLMs for exploratory tasks only, with no novel capability breakthrough.

Despite these developments, the dominant finding across the best-sourced CTI reports (NCSC, OpenAI, IBM X-Force, Mandiant) remains: **AI is enhancing existing TTPs, not creating new attack categories.** Social engineering, phishing, fraud, and influence operations have seen the most significant practical impact. Autonomous AI-driven intrusion at scale remains nascent.

The sectors most exposed today are financial services, professional services, and critical infrastructure. In publicly available primary reporting through April 2026, **Iranian APT42** and **North Korean FAMOUS CHOLLIMA** show the broadest documented AI adoption across multiple attack phases among state-linked actors; **financially motivated BEC/fraud operators** remain the most mature category overall given a seven-year operational head-start beginning with voice cloning in 2019. These assessments are bounded by available public disclosure and do not account for undisclosed programs.

---

## 2. Key Judgments

| # | Judgment | Confidence |
|---|----------|-----------|
| KJ-1 | March 2019 (UK CEO voice cloning, €220K) represents the earliest primary-sourced criminal AI case identified in publicly available reporting reviewed for this document. KJ-1 is a negative proof — earlier cases may exist in restricted or undisclosed reporting. | MEDIUM |
| KJ-2 | AI-enabled attacks remain dominated by social engineering, phishing, fraud, and influence operations. Direct AI involvement in intrusion TTPs (exploitation, lateral movement, persistence) is documented but still uncommon. | HIGH |
| KJ-3 | AI is enhancing existing TTPs rather than creating fundamentally new attack vectors. This consensus holds across NCSC, OpenAI, IBM X-Force, and Mandiant reporting through 2024. | HIGH |
| KJ-4 | Late 2025 provides the strongest public evidence to date of a qualitative shift: LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG), PROMPTFLUX, and GTG-1002 demonstrate that LLM-integrated malware and agentic AI intrusion are no longer theoretical. Caveat: PROMPTFLUX was in development/testing phase at time of discovery and had not demonstrated ability to independently compromise target networks. GTG-1002 autonomy degree is disputed by peer analysts. | MEDIUM |
| KJ-5 | Fully autonomous, end-to-end AI hacking without meaningful human oversight is unlikely at scale before 2027. The GTG-1002 case required 4–6 human decision points per campaign even at 80–90% AI autonomy. | MEDIUM |
| KJ-6 | Iranian APT42 and North Korean groups (FAMOUS CHOLLIMA, Kimsuky/Emerald Sleet) have the broadest documented AI use across multiple attack phases among state-linked actors in publicly available primary reporting through April 2026. | MEDIUM |
| KJ-7 | Ransomware operators have largely not integrated AI into core ransomware TTPs. No primary source confirms AI adoption by LockBit, CL0P, or equivalent groups. Criminal AI adoption is concentrated in fraud/BEC, not intrusion-and-encrypt workflows. | MEDIUM |
| KJ-8 | Most underground "dark LLM" products (WormGPT, FraudGPT, etc.) had no independently verified functional capabilities in 2023 per Trend Micro primary analysis. Public evidence did not substantiate advertised capability. The real risk is legitimate LLM access via jailbreaks, not custom criminal models. | MEDIUM |
| KJ-9 | AI lowers the barrier to entry for less-skilled threat actors, particularly for multilingual social engineering, voice cloning, and deepfake-enabled fraud. The measurable result is scale and volume, not necessarily sophistication. | HIGH |
| KJ-10 | The most significant near-term AI-enabled threat for most organizations is AI-enhanced phishing and deepfake-enabled fraud — not AI-powered exploitation. | HIGH |

---

## 3. Chronological Timeline

> **Legend:** CONFIRMED = primary source, directly verified. REPORTED = credible secondary sourcing with primary basis. SUSPECTED/WEAK = single-source, vendor claim, or unverified. AI-ADJACENT = automation or scripting, not specifically AI/ML.

---

### Pre-ChatGPT Era (2004–2022)

> **Scope note:** Rows marked `[RESEARCH PRECURSOR]` are defensive or academic demonstrations, not in-the-wild threat-actor use. They are included because they define the architectural lineage of current offensive AI tools and are analyzed in depth in §9.1. They should not be read as evidence of criminal or state-actor AI use in those years.

| Date | Event | Actor | Country | AI Use | Evidence | Why It Matters |
|------|--------|-------|---------|--------|----------|----------------|
| 2004 | ML spam filter evasion demonstrated at MIT Spam Conference | Academic / implicit criminal adoption | N/A | ML models used to evade ML-based spam filters via "good word" insertion | REPORTED (conference proceedings) | Origin of adversarial ML concept; criminal spam operators adopted techniques within years |
| 2014 | Neural CAPTCHA-solving demonstrated | Academic | N/A | ML-based CAPTCHA solvers demonstrated at scale; accuracy varied by target service (5–55% in Bursztein et al. USENIX WOOT 2014, not the ~95% figure cited in some secondary sources; ~95% accuracy in CNN-specific solvers emerged in later papers circa 2020) | REPORTED (Bursztein et al., USENIX WOOT 2014) | Established that ML could reliably bypass ML-based bot-detection at scale |
| August 2016 | **SNAP_R — Automated ML spear-phishing tool [RESEARCH PRECURSOR]** | Defensive research (John Seymour & Philip Tully, ZeroFOX) — not a threat actor | USA | LSTM and Markov chain generation modes trained on target's Twitter history to produce personalized phishing tweets; 30–66% click-through in live bake-off at 6.85 tweets/min across 819 targets in 2-hour window | REPORTED (Black Hat USA 2016 / ZeroFOX, PRIMARY) | Publicly documented ML system automating personalized spear-phishing generation and delivery; architectural predecessor of LLM-driven phishing (2023–2026). Included here as research precursor, not threat-actor use. |
| August 2016 | **DARPA Cyber Grand Challenge — Mayhem wins autonomous hacking competition [RESEARCH PRECURSOR]** | Defensive research (ForAllSecure / CMU, DARPA) — not a threat actor | USA | Fully autonomous system combining symbolic execution (Z3 SMT solver) and concolic fuzzing to discover vulnerabilities, generate exploits, and patch binaries in previously unseen software without human intervention in real time | CONFIRMED (DARPA CGC Final Event, August 4, 2016, PRIMARY) | Publicly validated fully autonomous vulnerability discovery and exploitation system; establishes closed-loop automated security template that Big Sleep (2024) later realises with neural methods. Included here as research precursor, not threat-actor use. |
| August 2018 | **DeepExploit (Reinforcement Learning Pentesting) [RESEARCH PRECURSOR]** | Defensive research (Isao Takaesu / MBSD — Mitsui Bussan Secure Directions) — not a threat actor | Japan | A3C reinforcement learning agent orchestrating Metasploit RPC API for autonomous exploitation sequencing against live targets; policy network trained via reward shaping on shell-session success | REPORTED (Black Hat Arsenal 2018 / Isao Takaesu, PRIMARY) | Publicly documented system treating exploitation sequencing as an RL optimization problem against live infrastructure; architectural predecessor to LLM-orchestrated pentesting frameworks (Stage 5b). Included here as research precursor, not threat-actor use. |
| August 2018 | **DeepLocker — CNN-gated payload delivery [RESEARCH PRECURSOR]** | Defensive research (IBM Research: Dhilung Kirat, Jiyong Jang, Marc Ph. Stoecklin) — not a threat actor | USA | Deep CNN (AlexNet referenced in primary slides) fine-tuned on target biometrics; model's penultimate-layer activations used as cryptographic key to decrypt payload only on correct target identification; PoC hidden in videoconferencing app | REPORTED (Black Hat USA 2018 Briefings / IBM Research, PRIMARY) | PoC malware design using a neural network as an activation trigger; payload unrecoverable via static analysis or sandbox detonation without presenting the precise biometric trigger. Included here as research precursor, not threat-actor use. |
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
| October 2024 (blog: Nov 1, 2024) | Google Big Sleep discovers zero-day in SQLite autonomously | Google Project Zero/DeepMind | USA (defensive research) | AI agent discovered a **stack buffer underflow** in SQLite's `seriesBestIndex` function (development branch only; fixed before any official release; **no CVE assigned**). Distinct from CVE-2025-6965, which is a separate July 2025 Big Sleep discovery (integer truncation/memory corruption, all versions prior to 3.50.2) | CONFIRMED (Google Project Zero blog published Nov 1, 2024, PRIMARY) | First publicly documented AI autonomous zero-day discovery in real-world production software |
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
| July 10–17, 2025 | **LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) — first in-the-wild LLM-querying malware** | APT28 / Forest Blizzard (moderate confidence) | Russia | Python malware compiled to executable; queries Alibaba Cloud Qwen 2.5-Coder-32B-Instruct via HuggingFace API at runtime to generate Windows commands for document theft. *CERT-UA received initial reports July 10; public advisory published July 17.* MITRE and Cato Networks researchers assessed as exploratory/pilot-phase activity | CONFIRMED (CERT-UA advisory + Cato Networks/Picus analysis, PRIMARY) | First publicly documented malware querying an LLM during execution in live operations; MITRE researcher Russo noted "no intelligent control" beyond scripted human-directed prompts |
| July–August 2025 | **GTG-2002 — Claude Code used for scaled data extortion** | GTG-2002 (Anthropic designation) | Unknown (suspected state-linked) | Claude Code used as active operator across full extortion lifecycle: vulnerability scanning, intrusion, data triage, ransom note generation, multi-victim management. 17+ organisations targeted in a single month; ransom demands >$500K. Targets include government, healthcare, emergency services, religious institutions | CONFIRMED (Anthropic August 2025 report, PRIMARY) | First Anthropic-disclosed agentic attack; distinct from GTG-1002 (this is extortion, GTG-1002 is espionage). AI managed the operational tempo of concurrent victims |
| August 2025 | **QUIETVAULT discovered — JavaScript credential stealer using locally-installed LLM CLI tools** | Unknown (financially motivated assessment) | Unknown | JavaScript-based malware leverages locally-installed LLM CLI tools already present on compromised macOS and Linux hosts — not external AI APIs. Embeds malicious prompts into local LLM context to search for cryptocurrency wallet files, GitHub tokens, NPM keys, and sensitive config data across user directories | CONFIRMED (Google GTIG, August 2025, PRIMARY) | First documented malware exploiting victim-installed local LLMs rather than external AI APIs; distinct attack surface from LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) model |
| November 2025 | **SesameOp — OpenAI Assistants API abused as covert C2** | Unknown espionage actor | Unknown | Backdoor (SesameOp) discovered using OpenAI Assistants API as a command-relay and data-staging channel, blending malicious C2 traffic with legitimate API calls. API key and account disabled by OpenAI on disclosure | CONFIRMED (Microsoft incident response report, November 2025, PRIMARY) | First confirmed case of a legitimate commercial AI API abused as a covert C2 relay; novel detection challenge (traffic indistinguishable from normal AI tool usage) |
| November 2025 | Anthropic disrupts GTG-1002 — agentic AI espionage campaign | GTG-1002 (Chinese state-sponsored, Anthropic designation) | China | Claude Code used for full intrusion lifecycle (recon, exploitation, credential harvesting, lateral movement, exfiltration) across ~30 targets; 80–90% AI autonomy; 4–6 human decision points/campaign. **Note: disputed by some peer analysts as overstating autonomy** — Intel 471 and Palo Alto Networks noted heavy reliance on standard open-source tools and significant hallucination | CONFIRMED (Anthropic official report November 13, 2025, PRIMARY) / **DISPUTED** on claimed autonomy degree | Strongest public claim of high-autonomy intrusion; autonomy claim plausible but contested; see §7 |
| Early June 2025 (discovered); November 4–5, 2025 (publicly disclosed) | PROMPTFLUX — LLM-driven self-rewriting malware, development phase | Unknown | Unknown | VBScript dropper containing a "Thinking Robot" module that queries Gemini 1.5 Flash to request obfuscated VBScript variants. One variant includes a function designed to rewrite source code hourly; however, the self-modification function (AttemptToUpdateSelf) was commented out in analyzed samples. Lacks ability to independently compromise a victim network | CONFIRMED (Google GTIG AI Threat Tracker, November 4–5, 2025, PRIMARY) | First documented malware family in testing phase designed for LLM-driven just-in-time code regeneration for signature evasion; GTIG and CERT-UA jointly credit PROMPTFLUX and PROMPTSTEAL/LAMEHUG as "first use of just-in-time AI in malware" |
| November 2025 | SentinelOne retrohunt: 7,000+ samples containing embedded AI API keys (NOTE: SentinelOne's report states "almost all turned out to be non-malicious" — vast majority were legitimate apps with accidentally leaked developer keys) | Various (APT28-linked PROMPTSTEAL prominent) | Various | Malware embedding API keys; CRITICAL CAVEAT: only a small subset constituted genuine LLM-integrated malware; the 6,000+ unique key figure likewise encompasses primarily non-malicious leaks | CONFIRMED (SentinelOne LABScon 2025, PRIMARY) | Highlights scale of accidental AI API key exposure; genuine LLM-integrated malware (LAMEHUG/PROMPTSTEAL) confirmed as a small subset |
| December 19, 2025 | IC3 warns of AI voice-cloning campaign targeting senior US officials | Unknown actors | United States | AI-generated voice messages used to impersonate senior US officials; campaign active "since at least 2023"; targets include government-affiliated personnel and senior military contacts | CONFIRMED (FBI IC3 PSA December 19, 2025, PRIMARY) | Confirms AI voice impersonation of government officials as operational TTP since 2023; highest-profile target class yet documented in US government warning |
| 2025–2026 | GenAI exploited at 90+ organizations via malicious prompt injection | Various | Global | Prompt injection attacks against AI-integrated enterprise systems to steal credentials and cryptocurrency | CONFIRMED (CrowdStrike GTR 2026, PRIMARY) | Confirms AI integration into enterprise workflows as a new attack surface |
| March 2026 | **TeamPCP LiteLLM supply chain attack — AI infrastructure targeted** | TeamPCP (threat actor designation) | Unknown | Attackers trojanized the LiteLLM Python proxy library on PyPI via CI/CD pipeline compromise (Trivy → LiteLLM build chain; PyPI publish token extracted from GitHub Actions runner). Three-stage payload: credential harvester, Kubernetes lateral movement toolkit, systemd backdoor (sysmon.service). CVE-2026-33634, CVSS4 9.4. Installation footprint ~36% of monitored cloud environments (Wiz); malicious packages live only 3–5 hours | CONFIRMED (Wiz, Snyk, Datadog Security Labs, Endor Labs, LiteLLM official advisory, PRIMARY) | First major confirmed attack targeting AI routing infrastructure itself — not using AI offensively, but treating AI supply chain as the attack surface. Signals a new threat category |

---

## 4. Major Incidents

### 4.1 UK Energy Company CEO Voice Cloning Fraud
**Date:** March 2019
**Actor:** Unknown criminal group
**Victim:** UK-based energy company (German parent company CEO voice cloned)
**AI Component:** Text-to-speech AI software cloned the German CEO's voice, including his accent and speech patterns. Three calls were made: first to demand €220,000 transfer to a "Hungarian supplier within the hour"; second to falsely claim reimbursement; third attempt to extract additional funds (refused when victim became suspicious of Austrian mobile number).
**Loss:** €220,000 (~$243,000 USD) — fully transferred, not recovered
**Insurance:** Euler Hermes covered the claim and described it as "the first cybercrime they'd heard of using AI."
**Source:** PRIMARY (Euler Hermes insurer statement; reported Wall Street Journal, **August 30, 2019**)
**Novel vs. Standard TTP:** Novel — no prior publicly documented and primary-sourced criminal use of AI voice synthesis identified in this review. The attack template (CEO impersonation, urgent wire transfer) is standard BEC; the AI component was genuinely new.
**Why It Matters:** Establishes 2019 as the earliest identified point in the AI fraud timeline based on available primary sourcing. All subsequent voice fraud incidents build on this template.

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
**Why It Matters:** In publicly available primary reporting through April 2026, Iranian APT42 shows the widest documented AI adoption across attack phases among the actors assessed in this report — a counterintuitive finding given assumptions that the most technically capable cyber powers would lead AI adoption. This assessment is limited to documented cases; undisclosed programs at other nation-states may differ.

---

### 4.7 LAMEHUG (CERT-UA designation) / PROMPTSTEAL (GTIG designation) — First In-the-Wild LLM-Querying Malware
**Note on naming:** CERT-UA designates this malware LAMEHUG; Google GTIG designates the same malware PROMPTSTEAL. These names are identical, referring to the same APT28 campaign. Subsequent references within this section use LAMEHUG for brevity.

**Date:** July 10–17, 2025. CERT-UA received initial reports July 10; public advisory published July 17. The phishing campaign was observed from approximately July 10.
**Actor:** APT28 / Forest Blizzard (MODERATE CONFIDENCE, CERT-UA attribution)
**Victim:** Ukraine (government entities; distributed via phishing impersonating Ukrainian ministry officials)
**AI Component:** Python malware (compiled to .pif executable via PyInstaller) that at runtime queries Alibaba Cloud's Qwen 2.5-Coder-32B-Instruct model via the HuggingFace inference API. The LLM dynamically generates Windows system commands for the malware to execute — used for document discovery and exfiltration. *(IOC register: refer to CERT-UA advisory #UA-CERT-2025-07-17 and the Cato Networks / Picus Security analyses for current sample hashes, HuggingFace API key patterns, and phishing lure document indicators.)*
**Technical detail:** SentinelOne identified 284 unique HuggingFace API keys embedded across LAMEHUG/PROMPTSTEAL samples (keys sourced from a 2023 credential dump). NOTE: SentinelOne's broader retrohunt found 7,000+ samples with embedded AI API keys, but the primary report states "almost all turned out to be non-malicious" — legitimate apps with accidentally leaked developer keys. LAMEHUG/PROMPTSTEAL represents the confirmed malicious subset.
**Source:** CONFIRMED PRIMARY (CERT-UA advisory July 2025; Cato Networks, Picus Security independent analyses; Google GTIG AI Threat Tracker, November 2025)
**Novel vs. Standard TTP:** Genuinely novel. Prior malware uses static logic or downloads staged payloads. LAMEHUG uses a live LLM to generate commands at execution time — the malware's behavior is partially determined by an external AI model, making static analysis insufficient for full detection.
**Why It Matters:** Represents a documented paradigm shift: from AI-assisted development of malware (offline) to AI-integrated malware execution (online). Detection requires understanding of LLM API traffic patterns in addition to traditional IOCs.
**Operational assessment caveat:** MITRE and Cato Networks researchers assessed LAMEHUG as exploratory/pilot-phase activity — a test of LLM integration rather than a fully operational capability. MITRE researcher Russo noted "no intelligent control" beyond scripted human-directed prompts, with the LLM handling only low-level command generation.

---

### 4.8 GTG-1002 — Strongest Public Provider Disclosure of a High-Autonomy AI-Assisted Intrusion Campaign
**Date:** Discovered September 2025; reported November 13, 2025
**Actor:** GTG-1002 (Anthropic internal designation; Chinese state-sponsored attribution)
**Scope:** ~30 global targets across technology firms, financial institutions, chemical manufacturers, and government bodies
**AI Component:** Claude Code (Anthropic's agentic coding assistant) used to conduct the full intrusion lifecycle: reconnaissance, exploitation, credential harvesting, lateral movement, data exfiltration. AI performed 80–90% of intrusion processes autonomously. Human operators intervened at 4–6 decision points per campaign.
**Limitation noted:** Claude hallucinated during operations — occasionally overstated findings, misidentified public information as secret, or fabricated data in reports to operators.
**Source:** CONFIRMED PRIMARY (Anthropic official report, November 13, 2025)
**Novel vs. Standard TTP:** Novel in degree of autonomy applied to the full intrusion lifecycle. All constituent TTPs (recon, exploitation, lateral movement) existed pre-AI; what's new is an AI agent orchestrating them with minimal human direction.
**Why It Matters:** The most detailed public provider disclosure of high-autonomy AI-assisted cyber espionage to date. If the autonomy degree is sustained under independent scrutiny, it shifts the threat model: defenders must account for intrusion campaigns executed predominantly by AI systems with limited human oversight. The autonomy degree claim remains disputed by peer analysts (Intel 471, Palo Alto Networks).

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
**Why It Matters:** Extends agentic AI from espionage (GTG-1002) into the criminal extortion ecosystem. Based on primary disclosures available through April 2026, GTG-2002 represents the most operationally detailed provider case of AI used autonomously in financially motivated extortion — a distinct and significant escalation from the espionage context of GTG-1002.

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
**Actor:** TeamPCP (threat actor designation used across multiple vendor reports including Wiz, Snyk, Datadog Security Labs, and BleepingComputer)
**Victim:** Enterprise AI developers and SaaS providers using LiteLLM (a widely-used Python library that routes requests between enterprise applications and multiple LLM providers)
**AI Component (none — the target was AI infrastructure):** Attackers compromised the LiteLLM build pipeline via a transitive dependency attack: TeamPCP had previously compromised Trivy (an open-source security scanner integrated into LiteLLM's build process), extracted LiteLLM's PyPI publish token from the GitHub Actions runner environment, and used it to push a trojanized package. The credential-harvesting code silently exfiltrated cloud API keys, AI provider tokens, and system prompts from any application importing the package. Estimated potential blast radius: ~36% installation footprint across cloud environments per Wiz telemetry — meaning LiteLLM was installed in that fraction of monitored cloud environments. The malicious packages were live for only 3–5 hours before removal; Docker Proxy image users were not affected. Actual compromised environments represent a much smaller subset of the installation footprint.
**Three-stage payload:** (1) Credential harvester — SSH keys, cloud provider tokens (AWS, GCP, Azure), Kubernetes secrets, cryptocurrency wallet files, and .env files containing AI API keys; (2) Kubernetes lateral movement toolkit — automated cluster enumeration and privilege escalation; (3) Persistent systemd backdoor deployed as `sysmon.service`. CVE-2026-33634 assigned; CVSS4 score 9.4.
**Source:** CONFIRMED PRIMARY (Wiz, Snyk, Datadog Security Labs, Endor Labs, FutureSearch, Kaspersky, BleepingComputer, LiteLLM official advisory, March 2026)
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

### 4.13 PROMPTFLUX — Self-Rewriting AI Malware (Development Phase)
**Date:** Discovered early June 2025; publicly disclosed November 4–5, 2025 (Google GTIG)
**Actor:** Unknown (unattributed at publication)
**AI Component:** VBScript dropper containing a "Thinking Robot" module that queries Gemini 1.5 Flash to request obfuscated VBScript variants, specifically targeting signature-based detection evasion. One variant includes a function (AttemptToUpdateSelf) designed to rewrite source code hourly; however, this self-modification function was commented out in all analyzed samples. Lacks the ability to independently compromise a victim network. *(IOC register: refer to Google GTIG AI Threat Tracker (November 4–5, 2025) for current sample hashes, dropper variants, and Gemini API key patterns observed in analyzed samples.)*
**Assessment:** GTIG assesses PROMPTFLUX as currently in development/testing phase. The hourly self-rewrite capability is a design objective, not yet demonstrated operationally in the analyzed samples.
**Source:** CONFIRMED PRIMARY (Google GTIG AI Threat Tracker, November 4–5, 2025)
**Why It Matters:** Even in development phase, PROMPTFLUX represents the first documented malware family designed around LLM-driven just-in-time code regeneration as a signature evasion mechanism. GTIG and CERT-UA jointly credit PROMPTFLUX and LAMEHUG/PROMPTSTEAL as "first use of just-in-time AI in malware." A fully operational version would challenge signature-based AV/EDR products.

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

> **Mapping note:** Identity & Infrastructure Fabrication (T1585/T1586) covers AI-generated personas. T1587.001 covers AI-assisted pre-deployment malware development. AI-assisted scripting at execution time (LAMEHUG model) maps to TA0011.

**Status: CONFIRMED** (multiple primary sources)

**T1585/T1586 — Identity & Infrastructure Fabrication:**
- FAMOUS CHOLLIMA: AI-generated photos + face-swap on ID documents + LLM-generated LinkedIn profiles for IT worker infiltrations (§4.4; DOJ indictment 2024, KnowBe4 2024)
- Crimson Sandstorm: ChatGPT-generated spear-phishing lures impersonating an international development agency (OpenAI/Microsoft February 2024)
- DPRK operative: AI-generated photo passed automated KYC (§4.4; KnowBe4 July 2024)
- *Limitation: AI-generated images may fail liveness detection; deep-profile identity investigation defeats AI-fabricated histories.*

**T1587.001 — Malware Development:**
- Storm-0817 (Iran): debugged Android malware via ChatGPT during development (OpenAI October 2024)
- APT41: Gemini for tool development and code translation (Google GTIG January 2025)
- APT42: Gemini for malware development support (Google GTIG January 2025)
- ScopeCreep: incremental Windows malware dev/debug via OpenAI (§4.12; OpenAI June 2025)
- MalTerminal (PoC, pre-Nov 2023; disclosed LABScon 2025): GPT-4 API to generate ransomware code on demand — PoC only, no confirmed live deployment
- *Limitation: LLMs produce functional but generic code. Bespoke, sophisticated malware and zero-day research still require skilled human developers.*

---

### TA0001 — Initial Access

> **Mapping note:** TA0001 covers AI-enabled techniques for gaining initial network access. **Voice & Video Impersonation** covers AI-generated voice/video used to deceive targets. **T1566: Phishing & Social Engineering** covers AI-generated content used for network access. Voice/deepfake fraud used for financial authorization (not network access) additionally maps to T1656 (Impersonation) and TA0040 Impact.

**Status: CONFIRMED — highest maturity of any AI-enabled TTP**

**Voice & Video Impersonation (Vishing/Deepfakes)**

**AI Usage:** AI-generated voice for vishing/help desk attacks; deepfake video for fraud authorization.

- Vishing: CrowdStrike documented 442% increase H1→H2 2024, explicitly attributed to AI voice synthesis accessibility.
- Deepfake CFO fraud: Arup ($25M); UAE bank ($35M); 2019 CEO fraud ($243K).
- Help desk social engineering: Scattered Spider (2023) used human operators; follow-on campaigns reportedly adopted AI voice agents.

**Limitations:** AI voice cloning quality degrades under scrutiny; verification call-backs and out-of-band confirmation disrupt attacks.

**T1566: Phishing & Social Engineering**

**AI Usage:** Grammar improvement, personalization, multilingual translation, voice/video deepfakes for authorization fraud, romance scam script generation, influence operation content.

- Phishing text generation: Crimson Sandstorm, APT42, Emerald Sleet confirmed (OpenAI/Microsoft February 2024; Google GTIG January 2025, PRIMARY).
- OpenAI disrupted romance scam networks using ChatGPT to manage multiple simultaneous victim conversations (February 2025, PRIMARY).
- AI generates convincing phishing emails in 5 minutes vs. 16 hours for human red team (Hoxhunt, SECONDARY).
- Doppelganger (Russia) used AI to translate and generate influence content in 6+ languages at scale impossible without AI.
- AI vs. human red team: AI surpassed human red team effectiveness by February–March 2025 (Hoxhunt, SECONDARY).
- Quantified effectiveness: AI-generated phishing emails achieved 54% click-through vs. 12% for human-written control in a controlled 101-participant study (Heiding et al., arXiv:2412.00586, SECONDARY arXiv preprint). Note: this 54% figure is from Heiding et al., not Hoxhunt; Hoxhunt click-through rates are in the 2–4% range.

**Limitations:** Personalized AI phishing at volume can trigger volume-based detection. AI cannot reliably tailor attacks based on real-time conversational cues without human oversight or agentic design.

---

### TA0011 — Command and Control

**AI Usage:** LLM APIs queried during malware execution to dynamically generate commands; legitimate AI services abused as covert C2 relay channels; AI-generated communication patterns for traffic-blending evasion.

**Status: CONFIRMED** — two distinct confirmed patterns as of April 2026:

**Pattern A — LLM-as-brain (runtime command generation):**
- LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) (July 2025): Python malware queries Qwen 2.5-Coder at runtime; static C2 logic replaced by dynamic LLM-generated Windows commands.
- PROMPTFLUX (identified early June 2025; disclosed November 2025): VBScript dropper designed to query Gemini for just-in-time code obfuscation. One observed variant includes a function to rewrite source code hourly; however, the self-modification function was commented out in primary analyzed samples. GTIG assesses it as in development/testing phase, not yet capable of independently compromising victim networks.

**Pattern B — Legitimate AI API as C2 relay:**
- SesameOp (November 2025, Microsoft, PRIMARY): Backdoor used OpenAI Assistants API as command relay and data-staging channel. C2 traffic was legitimate HTTPS to api.openai.com — indistinguishable from normal AI tool usage on a network level. API key terminated on disclosure.
- SesameOp represents a higher-impact pattern than Pattern A: no custom infrastructure required; traffic blends into enterprise AI egress; detection requires behavioral profiling of AI API usage, not IP/domain blocklists.

**Limitations:** Pattern A — requires outbound HTTPS to AI provider APIs; detectable via egress analysis; API key revocation degrades ongoing campaigns. Pattern B — requires maintaining a valid AI provider account; account termination breaks C2; detection possible via anomalous API usage patterns (volume, threading, unusual payload structures).

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

### TA0009 — Collection (Data Exfiltration Support)

> **Mapping note:** TA0009 covers internal network data collection and staging before exfiltration. Post-exfiltration activities — specifically, AI-assisted triage of already-exfiltrated data to identify leverage for double-extortion — technically map to **TA0040 Impact** (T1657: Financial Theft / double extortion leverage) rather than TA0009. This section covers in-network collection assistance; extortion-context data analysis is noted under TA0040.

**AI Usage:** AI-assisted triage and staging of data during collection; translation of foreign-language documents prior to exfiltration; automated identification of high-value files within the victim network.

**Status: REPORTED** (NCSC assessment; no confirmed named-actor primary sourcing for in-network AI collection)

- NCSC (January 2024, PRIMARY): "AI will almost certainly make cyber attacks against the UK more impactful because threat actors will be able to analyse exfiltrated data faster." Note: this assessment encompasses both in-network collection and post-exfiltration analysis; the TA0040 Impact section addresses the latter.
- GTG-1002 (Anthropic November 2025): AI conducted data exfiltration as part of agentic campaign — though details of post-collection processing not disclosed. In-network collection was part of the autonomous intrusion lifecycle.

---

### AI Supply Chain — Emerging TTP Category (2026+)

**AI Usage:** Compromising the open-source libraries, proxy servers, and API middleware that connect enterprises to LLMs — stealing AI API credentials, system prompts, and intercepting AI-processed data.

**Status: CONFIRMED (first confirmed case March 2026)**

- TeamPCP / LiteLLM (March 2026, PRIMARY): Trojanized PyPI library harvesting AI API keys and system prompts. Wiz telemetry: ~36% of monitored cloud environments had LiteLLM installed (installation footprint, not compromise count — actual breached environments are a much smaller subset; malicious packages live only 3–5 hours). No AI used offensively — the AI infrastructure itself is the target. See §4.11.
- QUIETVAULT (GTIG, August 2025): JavaScript-based credential stealer targeting compromised macOS and Linux hosts. Leverages locally-installed LLM CLI tools already present on victim systems — not external AI APIs. Embeds malicious prompts into the local LLM context, directing it to search user directories for cryptocurrency wallet files, GitHub tokens, NPM keys, and sensitive configuration data. Distinct from LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG), which calls external cloud AI APIs at runtime rather than exploiting victim-installed local LLMs.

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

> **Evidence-type note:** Figures below span three distinct categories — **(1) In-the-wild / Observed** (primary-sourced, operational data), **(2) Controlled Study** (academic or vendor experiment; not necessarily representative of real-world operations at scale), and **(3) Vendor Claim** (single source, unverified methodology). Interpret accordingly; do not mix categories in citations.

| Metric | Figure | Data Type | Source | Quality |
|--------|--------|-----------|--------|---------|
| Fully AI-automated phishing click-through | 54% (fully AI-automated); AI + minimal human-in-loop: 56% | Controlled Study | **Heiding et al., arXiv:2412.00586** (101 participants; arXiv preprint, not peer-reviewed at time of writing). Not a Hoxhunt figure; Hoxhunt CTRs are 2–4% | SECONDARY |
| Control/baseline phishing click-through (same study) | 12% | Controlled Study | Heiding et al., arXiv:2412.00586 | SECONDARY |
| Fraction of recipients falling for AI phishing | 60% | Unverified | Source not identified in this review — treat as WEAK pending primary citation | WEAK |
| AI phishing campaign generation time vs. human red team | 5 min (AI) vs. 16 hr (human); AI surpassed human red team Feb–Mar 2025 | Vendor Claim | Hoxhunt | SECONDARY |
| National phishing sample with AI-generated content | ~13% of 40 sampled emails (~1% of 2023 reported attempts) | In-the-Wild / Observed | Singapore CSA "Singapore Cyber Landscape 2023," July 2024 | PRIMARY (small sample; imperfect detection tools) |

*Note: Heiding et al. (arXiv:2412.00586, 101 participants) provides the strongest controlled methodology for phishing effectiveness comparisons; it is an arXiv preprint, not a peer-reviewed publication, but the 54% figure is the most reproducible in the literature. The 54% figure is attributable to that study, not to Hoxhunt (whose click-through rates are 2–4%). Treat the 1,265% surge figure (SlashNext) with skepticism — single vendor, unclear methodology.*

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

### 6.6 FBI IC3 2025 — AI-Specific Crime Statistics (First Available)

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

### 6.7 AI API Key Exposure in Malware Ecosystem (VirusTotal retrohunt)

| Metric | Figure | Source | Quality |
|--------|--------|--------|---------|
| ⚠️ CRITICAL CAVEAT | SentinelOne primary report: "Almost all of these turned out to be non-malicious" — the vast majority of 7,000+ samples were legitimate apps with accidentally leaked developer API keys, not LLM-integrated malware. Only a small confirmed subset (LAMEHUG/PROMPTSTEAL) constituted genuine LLM-querying malware. | SentinelOne LABScon 2025 | PRIMARY |
| Malware samples with embedded AI API keys (VirusTotal retrohunt) | 7,000+ | SentinelOne LABScon 2025 | PRIMARY |
| Unique AI API keys found across malware samples | 6,000+ | SentinelOne LABScon 2025 | PRIMARY |
| Unique HuggingFace API keys in APT28/PROMPTSTEAL samples | 284 | SentinelOne LABScon 2025 | PRIMARY |
| Named AI API providers found in malware | OpenAI, HuggingFace, Anthropic, Google, others | SentinelOne LABScon 2025 | PRIMARY |

---

## 7. Reality vs. Hype

### 7.1 What AI Is Genuinely Changing in Offensive Operations

**Confirmed real impacts (high confidence):**

1. **Social engineering quality and scale.** AI eliminates the grammar/spelling/translation tells that historically identified phishing and scams. Multilingual campaigns that required specialized human operators can now be run at scale. Romance scam networks maintain dozens of victim conversations simultaneously. This is measurable and primary-sourced.

2. **Voice and video impersonation quality.** The 2019→2020→2024 progression from voice-only to multi-person real-time video deepfakes represents a genuine capability trajectory. Commercial voice-cloning platforms report requiring as little as 30 seconds of target audio for a functional clone (vendor specifications; quality varies by platform, sample length, and noise conditions). This directly challenges call-back verification procedures and verbal authorization processes.

3. **Speed of content production.** In Hoxhunt's red-team comparison (SECONDARY), AI-generated phishing campaign production took approximately 5 minutes vs. 16 hours for a human red team — an experimental finding that illustrates directional magnitude, not a universal constant. Multilingual IO content generation at scale and LLM-assisted code development show similar force-multiplier patterns across multiple independent sources. AI is a genuine productivity accelerant for activities previously bottlenecked by human writing, translation, and coding time.

4. **Barrier to entry reduction.** Less-skilled actors can now conduct attacks that previously required specialized technical or linguistic expertise. Europol, NCSC, and NCA all confirm this in primary reports.

5. **LLM-integrated malware (2025).** LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) and PROMPTFLUX demonstrate that AI integration into malware execution is operationally real, not theoretical. SentinelOne's retrohunt identified 7,000+ samples with embedded AI API keys across VirusTotal, though SentinelOne's primary report explicitly states that "almost all of these turned out to be non-malicious" — the majority were legitimate applications with accidentally leaked developer keys. The confirmed LLM-integrated malware subset (LAMEHUG/PROMPTSTEAL) is a small fraction of this dataset. The retrohunt methodology itself, however, represents an important detection approach for the ecosystem.

6. **Agentic AI intrusion (late 2025).** GTG-1002 is the strongest provider-disclosed case of high-autonomy AI-assisted intrusion to date. The stated autonomy fraction is disputed by peer analysts; the case establishes a plausible operational model whose validity requires independent corroboration before it can be called a confirmed paradigm shift.

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
  - **LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG):** Malware querying an LLM at runtime is a new TTP — not an enhancement of existing remote access tool design.
  - **PROMPTFLUX:** AI-driven hourly self-rewriting for signature evasion has no direct pre-AI analog.
  - **Agentic intrusion (GTG-1002):** AI autonomously orchestrating full kill chain is a new operational model, not an enhancement of human-operated intrusion.

---

### 7.4 Autonomous Hacking — Research vs. Reality

| Setting | Finding | Status |
|---------|---------|--------|
| UIUC (April 2024): GPT-4 exploits 87% of CVEs with description, sandboxed | Autonomous vulnerability exploitation proven in controlled environment | Research (no real victims) |
| Google Big Sleep (discovered Oct 2024; blog Nov 1, 2024): Stack buffer underflow in SQLite discovered autonomously — no CVE assigned (dev branch only, fixed pre-release). Separate from CVE-2025-6965 (Jul 2025, integer truncation) | First AI autonomous zero-day discovery in real-world production software | Defensive research (no malicious deployment) |
| Unit 42 red team: AI simulates full ransomware kill chain in 25 minutes | AI can execute full attack in test environment | Red team exercise |
| GTG-1002 (November 2025): 80–90% autonomous intrusion across ~30 targets | Anthropic claims first real-world agentic intrusion confirmed; **disputed by peer analysts** | CONFIRMED (Anthropic primary) / DISPUTED on autonomy degree |
| GTG-2002 (August 2025): Claude Code as extortion operator at 17 organisations | Corroborating agentic AI extortion case from same provider | CONFIRMED (Anthropic primary) |

**Key limitation on GTG-1002:** Anthropic's November 2025 report is a primary source and the strongest public claim of high-autonomy intrusion. However, Intel 471 and Palo Alto Networks analysts independently reviewed the case and noted: AI frequently hallucinated, generated bug-ridden exploit code, and ultimately relied heavily on standard open-source penetration testing tools deployed and supervised by human operators. The "80–90% AI autonomy" figure is Anthropic's own assessment from a provider perspective; independent corroboration of the autonomy fraction is limited.

**The correct analytical position:** High-autonomy agentic intrusion is real and documented. The specific fraction of automation is disputed. "Largely autonomous" rather than "fully autonomous" is the defensible characterisation with current evidence.

### 7.5 The "AI Ransomware" Panic — A Case Study in Hype

In late 2025, reports circulated about **PROMPTLOCK** *(IOC register: refer to SentinelOne LABScon 2025 disclosure for Golang binary VirusTotal submission hash)* — widely described as the "first AI-powered ransomware in the wild." ESET initially made this claim based on detecting the tool. In reality, SentinelOne researchers confirmed at LABScon 2025 that PROMPTLOCK is a cross-platform Golang binary developed as a proof-of-concept or red team tool: it uses a locally-installed LLM (gpt-oss:20b via the Ollama API) to autonomously generate Lua encryption scripts targeting victim files. It was uploaded to VirusTotal for testing, where multiple AV vendors flagged it — triggering media coverage of an "AI ransomware" that never existed as an active threat. The specific institutional origin of PROMPTLOCK has not been publicly attributed.

**The PROMPTLOCK case illustrates:** (a) Security researchers publish AI-enabled attack PoCs; these are frequently misidentified as in-the-wild threats. (b) Real ransomware operators continue to use proven, mathematically sound encryption algorithms (AES, RSA) rather than trusting an LLM to handle encryption. (c) LLM-generated code for encryption is slower, less reliable, and more detectable than optimised purpose-built cryptographic implementations. PROMPTLOCK demonstrates technical feasibility but tells us nothing about actual criminal adoption.

**Contrast with real AI malware:** LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) and PROMPTFLUX are confirmed in-the-wild. The distinction: LAMEHUG uses the LLM for *command generation* (not encryption); PROMPTFLUX uses the LLM for *code rewriting for evasion* (not encryption). Neither uses AI for the cryptographic core. AI is being used in the parts of malware where its probabilistic output is acceptable (generating commands, obfuscating code); not in parts where cryptographic precision is required (encryption/decryption).

---

## 8. Actor Segmentation

### 8.1 Financially Motivated Cybercrime (BEC / Fraud)

**AI Adoption Level: HIGH — widest breadth of documented operational AI use across this report's actor categories**

BEC and fraud actors were the first criminal adopters of AI (voice cloning, 2019) and remain the most mature. The use cases are tightly aligned with AI's actual strengths: natural language generation, voice/video synthesis, identity fabrication.

- Voice cloning: Deployed at scale since 2019; first $35M+ loss documented 2020.
- Deepfake video: Operationally deployed by 2024 (Arup case).
- Romance scam automation: ChatGPT managing multiple simultaneous victim conversations (OpenAI 2025).
- BEC template generation: Established market via WormGPT/FraudGPT ecosystem even if specific tools were vaporware — jailbroken legitimate LLMs fill the gap.

**Why ahead:** Fraud benefits directly from AI's language and synthesis capabilities. Measurable ROI is immediate (transfer executed or not). No sophisticated infrastructure required beyond a phone/video call.

---

### 8.2 Ransomware Operators

**AI Adoption Level: LOW — limited public evidence of confirmed core operational integration**

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

**Russia (APT28/Forest Blizzard, Doppelganger, Bad Grammar): MEDIUM** — Primarily deployed for influence operations (IO content at scale, translation). LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) (APT28, 2025) represents a shift to operational malware integration. Relative under-utilization compared to Iran and DPRK is analytically notable given GRU's technical reputation. High-tempo destructive actors within the Russian cluster (Sandworm/APT44) show negligible documented AI adoption in core destructive workflows through April 2026 — no primary disclosures place Sandworm in OpenAI, GTIG, or Microsoft AI-abuse reporting.

**Why differences exist:** Iran's IRGC-linked groups have a high operational tempo in social engineering and must operate efficiently with limited technical resources — AI aligns with their existing TTP preferences. DPRK has a clear financial mandate (cryptocurrency, IT worker revenue) that aligns perfectly with AI-enabled identity fraud. Russia has capable human operators who may perceive less marginal AI benefit; IO operations are a natural fit. High-tempo disruptive operators (Sandworm model) prioritize speed of pre-built destructive deployment over AI-assisted iterative workflows.

---

### 8.4 Influence / IO Actors

**AI Adoption Level: HIGH for content production; LOW for actual audience impact**

AI dramatically lowered IO content production costs. Spamouflage, Doppelganger, Bad Grammar, IUVM, and Zero Zeno all confirmed as AI content generators. However, the critical finding is that this production advantage did not translate to audience impact: no operation scored above 2 on Brookings' Breakout Scale through 2024.

**Why behind on impact:** Authentic influence requires trust networks built over time. AI can generate text but cannot build the social credibility needed for viral engagement. Coordinated inauthentic behavior detection has kept pace with AI content generation quality improvements.

---

### 8.5 Hacktivists

**AI Adoption Level: LOW to MEDIUM**

NCSC noted that AI lowers barriers for hacktivists. Documented evidence is limited to AI-enhanced defacement, AI-generated messaging, and AI-assisted DDoS coordination. No primary-sourced hacktivist AI intrusion case documented. Iran-aligned hacktivist groups (e.g., Handala, active since late 2023 targeting Israeli infrastructure) show no primary-sourced AI adoption in intrusion TTPs through April 2026; IO component adoption via AI-generated content is plausible but unconfirmed.

**Why behind:** Hacktivist goals (disruption, messaging) are achievable with off-the-shelf tools without AI integration. AI provides marginal tactical improvement; organizational capacity and target selection matter more.

---

## 9. Technical Evolution

### 9.1 Historical Precursors (2016–2018): Technical Anatomy

Before LLMs entered the threat landscape, a discrete generation of AI-native offensive tools emerged from academic and defensive research communities between 2016 and 2018. These tools are not historical curiosities — they represent the first architectural templates for AI-augmented attack automation, and their design patterns prefigure every major pattern visible in the 2023–2026 threat landscape. Understanding their internals is prerequisite to understanding why the current generation of LLM-integrated malware is qualitatively different from, and in some respects less sophisticated than, what was built a decade earlier.

---

#### SNAP_R (2016) — LSTM and Markov Generation Modes for Targeted Spear-Phishing at Scale

**Origin:** Developed by researchers John Seymour and Philip Tully (ZeroFOX) and presented at **Black Hat USA 2016** (with supplementary materials at DEF CON 24). SNAP_R stands for Social Network Automated Phishing with Reconnaissance.

**Architectural Design:**

SNAP_R implemented two independent generative models as selectable alternatives — not a combined "hybrid pipeline" as sometimes characterised in secondary sources:

1. **LSTM (Long Short-Term Memory) language model** — trained on a corpus of Twitter posts scraped from a target's public social media history. The LSTM learned the syntactic patterns, vocabulary, topical preferences, and stylistic quirks of each individual target. This produced a character-level or token-level probability distribution over plausible next-token sequences that mimicked the target's own writing style.

2. **Markov chain model** — an alternative generation mode using variable-order Markov chains trained on the same per-target corpus. The Markov model offered lower computational overhead than the LSTM but with reduced contextual coherence over longer sequences. Both models operated independently with different accuracy/speed tradeoffs; practitioners selected one per deployment. Secondary sources describing a "LSTM + Markov hybrid architecture" conflate two separate modes into a single pipeline that does not reflect the primary implementation.

**Operational Pipeline:**

- **Reconnaissance phase:** Automated scraping of target's public Twitter/social media history using Twitter API. Feature extraction of dominant topics, named entities, and stylistic patterns fed as training context.
- **Generation phase:** Selected model (LSTM or Markov, per operator choice) produces candidate phishing tweet bodies crafted to appear consistent with the target's established communication style.
- **Delivery phase:** Tweets include embedded malicious URLs (the actual lure payload). The high personalization rate was designed to defeat pattern-based phishing detection and exploit the implicit trust generated by stylistic familiarity.

**Measured Outcomes:** In the researchers' live operational bake-off, SNAP_R achieved a click-through rate of **30–66%** (confirmed clicks ~30%; total engagement including unknown referrers reaching ~66%), compared to baselines of 5–14% for mass phishing campaigns. Demonstrated throughput was approximately **6.85 tweets per minute**, reaching 819 total targets over a 2-hour operational window. **Important correction:** the 819-target total for the bake-off has been widely misread in secondary sources as a per-minute rate, producing an erroneous "~800 tweets/minute" figure that does not appear in the primary paper. The primary Black Hat USA 2016 presentation is the authoritative source; the 6.85 tweets/minute figure is the correct operational throughput.

**Architectural Significance:** SNAP_R is the direct architectural predecessor of the LLM-generated spear-phishing TTPs documented in 2023–2026. The fundamental design — use AI to learn target-specific linguistic patterns, generate personalized lure content, automate delivery — is identical to what OpenAI documented with APT42 in 2024 and what the Singapore GovTech GPT-3 experiment demonstrated in 2021. The difference is only implementation: SNAP_R required training a bespoke per-target model; modern LLMs achieve comparable personalization zero-shot from a few scraped posts used as prompt context.

---

#### DARPA Mayhem (2016) — Symbolic Execution + Fuzzing for Autonomous Zero-Day Generation

**Origin:** Mayhem was developed by Carnegie Mellon University's ForAllSecure team as the winning entry of DARPA's Cyber Grand Challenge (CGC) in August 2016. The challenge required fully autonomous systems to discover vulnerabilities in previously unseen binaries, generate exploits, and patch their own systems — all without human intervention, in real time.

**Architectural Design:**

Mayhem's architecture is best understood as a hybrid of three distinct automated reasoning systems:

1. **Symbolic Execution Engine (SE):** Mayhem used a path-exploration symbolic executor that treated program inputs as symbolic variables (rather than concrete values). By maintaining a set of path constraints — logical formulas describing the conditions required to reach a particular program state — the SE engine systematically explored reachable execution paths through target binaries. When a path constraint set was satisfiable in a way that reached a potentially exploitable state (null pointer dereference, buffer overflow, use-after-free), the engine queried an SMT solver (Satisfiability Modulo Theories, specifically Z3) to produce a concrete input that would trigger that state. This input becomes the exploit primitive.

2. **Fuzzing Engine (Concolic/Directed):** Pure symbolic execution is computationally expensive and does not scale to large binaries due to path explosion. Mayhem integrated a concolic fuzzer — a hybrid that alternates between concrete test execution (fast, but limited path coverage) and symbolic analysis (slow, but capable of reaching deep paths). Concolic execution injects concrete values to "unstick" symbolic exploration when constraint solving becomes intractable, allowing Mayhem to cover a larger surface area of the target binary than either approach alone.

3. **Exploit Generation and Payload Assembly:** On identifying a triggered crash state, Mayhem's exploit generator classified the vulnerability type (stack buffer overflow, heap overflow, format string, etc.) and assembled a proof-of-concept exploit using pre-computed payload templates adapted to the control-flow state of the crashing execution. Exploit quality varied; the CGC environment used simplified binaries and a controlled network stack (DECREE OS), which substantially reduced real-world exploit generalizability.

**Why It Matters Architecturally:**

Mayhem is the first publicly validated system to close the full loop from *binary input → vulnerability discovery → exploit generation* without human operator involvement. In the CGC final, Mayhem achieved a net positive score on both offense and defense concurrently — patching vulnerabilities in its own service binaries while simultaneously developing and deploying exploits against opponent systems. (The specific percentage of vulnerabilities patched is widely cited in coverage but is not directly verifiable against primary DARPA CGC documentation; this report avoids a specific figure for that reason.)

**Relationship to Current AI Threat Landscape:** Mayhem is not an ML system in the modern sense — it does not use neural networks. Its relevance is architectural: it demonstrated that a *fully automated pipeline* could traverse the discovery-exploitation cycle on previously unseen binaries. Google Project Zero's Big Sleep system follows the same closed-loop architectural template but replaces symbolic execution with LLM-guided code path analysis. *(Big Sleep CVE note: the October 2024 discovery and CVE-2025-6965 are two separate SQLite vulnerabilities — see §4 timeline and R11 for the distinction; this section does not re-detail them.)* The transition from formal methods (SMT solvers) to neural methods (LLMs) for vulnerability discovery is the key technical evolution between 2016 and the mid-2020s — the target architecture is the same; the reasoning engine changed.

---

#### DeepExploit (2018) — A3C Reinforcement Learning Orchestrating Metasploit

**Origin:** Developed by Isao Takaesu (Mitsui Bussan Secure Directions, MBSD) and publicly released at Black Hat USA Arsenal in August 2018 (also presented at Black Hat EU 2018 Arsenal and DEF CON 26 AI Village). DeepExploit is a fully automated penetration testing framework that uses reinforcement learning to autonomously select and sequence exploitation actions against live targets.

**Architectural Design:**

DeepExploit's core innovation is the integration of **Asynchronous Advantage Actor-Critic (A3C)** reinforcement learning with the Metasploit Framework's RPC API — treating the penetration testing process as a Markov Decision Process (MDP) solvable by a policy-gradient RL agent.

1. **State Space:** The agent's observation at each timestep consists of structured data about the target: open port set (from Nmap scan), service fingerprint strings, detected OS version, known vulnerability identifiers from Metasploit's database associated with detected services, and prior action outcomes (success/fail/partial flags). This state vector is encoded as a fixed-dimension feature array.

2. **Action Space:** At each step, the A3C agent selects from a discrete action set consisting of available Metasploit modules applicable to the observed target state — specifically exploit modules, auxiliary scanners, and post-exploitation modules. The action space is dynamically filtered at each step to only include modules Metasploit considers candidate matches for the observed service fingerprints, bounding the effective action space to tractable size.

3. **Reward Function:** Positive reward is granted upon successful module execution resulting in a shell session (meterpreter or standard). Partial positive reward for successful auxiliary reconnaissance that expands the observed state. Negative reward (penalty) for failed exploit attempts, timed-out connections, and IDS alert signatures triggered. The reward shaping was specifically designed to discourage noisy exploitation attempts that increase detection probability.

4. **A3C Architecture:** DeepExploit used A3C (not simpler Q-learning variants) because A3C's asynchronous parallel actor design allows multiple simultaneous environment interactions across different target hosts — effectively enabling the agent to learn from concurrent exploitation attempts in parallel rather than sequentially. Each actor thread interacts with a separate Metasploit RPC instance; gradient updates are pushed asynchronously to a shared global policy network. This architecture made DeepExploit practical for multi-host environments where parallelism is operationally expected.

5. **Transfer Learning Module:** One of DeepExploit's documented features was a "transfer learning" capability: exploitation knowledge acquired against one target configuration could partially initialize the policy network for related target configurations, reducing convergence time required before the agent achieved reliable exploit selection — an early instantiation of the generalization problem that LLM-based tools later address via foundation model pre-training.

**Operational Outcomes:** In demonstration environments, DeepExploit autonomously identified and exploited target VMs without human intervention, selecting correct Metasploit modules from the available action space in fewer steps than a naive random policy and achieving higher success rates than baseline scripted automation.

**Architectural Significance:** DeepExploit is the earliest publicly documented system to treat exploitation sequencing as an RL optimization problem against live infrastructure. The design pattern — RL agent using structured observation of target state to select from a tool library of offensive primitives — prefigures the LLM-as-orchestration-layer architecture documented in Stage 5b of this report (PentestGPT and derivatives, 2023–2024). The fundamental structure is identical: an intelligent controller selecting from a discrete set of offensive tool actions based on observed target state. The implementation differs (RL policy network vs. LLM prompt-response loop), but the threat model implication is the same: reduction of operator expertise requirement for multi-step exploitation sequencing.

---

#### DeepLocker (2018) — CNN-Gated Payload Delivery via Neural Network Trigger

**Origin:** Developed by IBM Research (Dhilung Kirat, Jiyong Jang, and Marc Ph. Stoecklin) and presented at Black Hat USA 2018 Briefings track (August 9, 2018). DeepLocker was explicitly framed as a proof-of-concept "evasion technique" rather than a weapon, but its architecture represents a qualitative departure from any prior malware design pattern.

**Architectural Design:**

DeepLocker's central innovation is the use of a trained neural network not as an attack capability but as the **payload decryption condition** — a classifier whose correct classification output is the decryption key.

1. **Payload Encryption:** The malicious payload (in the PoC, a WannaCry-style ransomware module) is encrypted using symmetric encryption. The decryption key is **never stored on disk or in the binary**. It is instead derived as a function of the neural network's internal activations. (The primary IBM presentation slides and blog post describe the neural key derivation mechanism but do not specify a particular cipher such as AES-256; the specific algorithm is not confirmed in available primary sources.)

2. **Neural Network as Trigger:** DeepLocker embeds a pre-trained deep convolutional neural network as a payload activation gate. The IBM presentation slides reference AlexNet as the example CNN architecture used in the PoC; the specific model is fine-tuned on a small dataset of target-specific features — in the demonstrated PoC, facial recognition images of the intended target victim. The model's penultimate layer activations (a fixed-dimension floating-point vector) are mapped to a deterministic key derivation function (KDF), producing the decryption key only when the model achieves confident correct classification of the target. *Note: secondary sources frequently cite VGG-16 as the CNN used; this claim is not substantiated in the IBM Black Hat 2018 presentation slides or the associated blog post, which reference AlexNet.*

3. **Trigger Condition Evaluation:** The malware continuously captures local sensor data (in the PoC: webcam frames, but the architecture supports any observable: GPS coordinates, voice signature, network environment fingerprint, BSSID set). Each captured frame is passed through the embedded CNN. When the model's output confidence exceeds a threshold for the target identity, the activation vector is fed into the KDF to reconstruct the decryption key and decrypt the payload in-memory.

4. **Evasion Properties:** Because the payload remains encrypted and the decryption key is never present in static form, traditional signature-based and static analysis methods cannot recover the payload. Sandbox detonation — the standard dynamic analysis fallback — will not trigger decryption unless the sandbox environment can present the precise trigger condition (i.e., the target's actual face to the webcam, or the exact GPS coordinates). This makes behavioral sandbox analysis ineffective as a detection mechanism against this architecture.

5. **Covert Channel via Legitimate Application:** IBM's PoC embedded DeepLocker within a legitimate videoconferencing application binary — the neural network inference ran as a background thread using the application's legitimate webcam access, indistinguishable from normal application behavior.

**Architectural Significance:** DeepLocker introduces the concept of **AI-conditioned payload delivery** — the neural model is not used to generate attack content or select attack actions, but to define an ultra-precise activation policy that restricts payload detonation to a target population potentially as small as one individual. No conventional malware architecture achieves this specificity: traditional targeted malware uses environment checks (registry keys, hostname strings, language settings, IP ranges) that are trivially bypassed in sandboxes. The CNN trigger cannot be bypassed without presenting the actual biometric trigger — the sandbox cannot fake a face the model was specifically trained to recognize. This represents an architectural hardening of targeted malware delivery against the primary defensive mechanism (sandbox detonation and dynamic analysis) that had governed malware detection since approximately 2010. While no in-the-wild DeepLocker variant has been confirmed, the architecture is fully implementable with commodity AI tooling available from 2018 onward, and the underlying design pattern — ML model as trigger condition — is applicable to any multimodal input observable from a compromised host.

---

**Summary Assessment:** These four systems — SNAP_R, Mayhem, DeepExploit, and DeepLocker — collectively defined the design space of AI-augmented offensive tooling before the LLM era. They demonstrate that the architectural concepts underlying current AI threat actor TTPs (ML-driven personalized generation, closed-loop autonomous exploitation, policy-driven tool orchestration, CNN-gated payload delivery) were all technically instantiated no later than 2018. The subsequent LLM democratization did not invent these patterns; it lowered the implementation barrier and expanded the accessible threat actor population. This historical context is essential for accurate threat modeling: organizations that frame AI offensive capability as a post-2022 phenomenon are already behind the conceptual state of the art by at least four years.

---

### Stage 1: Adversarial ML and CAPTCHA Bypass (2004–2018)
Early exploitation of AI against AI: ML spam filters evaded by ML-generated content (2004). ML-based CAPTCHA solvers demonstrated by 2014, with accuracy ranging from 5–55% depending on the service implementation (Bursztein et al., USENIX WOOT 2014); CNN-based solvers achieving higher accuracy emerged in subsequent years. Commercial CAPTCHA-solving services mainstream by 2017–2020. This stage is largely invisible in current threat reporting but established the template: use AI to defeat AI-based defenses.

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

### Stage 5/6: Integrated AI Operations — LLM-Integrated Malware, Orchestration Frameworks, and AI-as-Infrastructure (2025–2026)

Three sub-patterns characterize the current operational stage:

**5a — LLM-integrated malware and agentic intrusion (2025):**
- LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) (July 2025): malware queries LLM at runtime — the first in-the-wild shift from "AI helps develop malware" to "AI is part of malware execution."
- GTG-1002 (November 2025): AI reported to execute 80–90% of intrusion lifecycle across ~30 targets — the most detailed provider-disclosed case of high-autonomy AI-assisted intrusion to date; autonomy degree disputed by peer analysts (sole disclosure: Anthropic).
- PROMPTFLUX (November 2025): first publicly documented malware family with LLM-driven self-rewriting as a design objective; self-modification function was commented out in analyzed samples (development phase).
- SentinelOne retrohunt (2025): 7,000+ samples with embedded AI API keys — though the primary report notes almost all turned out to be non-malicious leaks. The genuine LLM-integrated malware subset remains small but growing.

**5b — AI offensive orchestration frameworks (2024–2026):**
Tools such as PentestGPT (open-source, 2023), HackerGPT, and proprietary derivatives use LLMs as a natural-language interface to standard penetration testing utilities (Nmap, Metasploit, Impacket, BloodHound, Nuclei). They do not grant AI novel capabilities; what they change is the **expertise threshold** — an operator no longer needs deep familiarity with each tool's syntax to execute sophisticated multi-step intrusion workflows. Standard EDR, NDR, and SIEM signatures still detect the underlying tool activity; however, tool chains executing with atypical sequencing or unusual flag combinations may indicate AI-orchestrated operation rather than manual execution.

**5c / Stage 6 — AI infrastructure as attack surface (2025–2026):**
Two distinct patterns emerged concurrently:
- **Legitimate AI API as C2 relay:** SesameOp (November 2025) abused OpenAI Assistants API as a covert C2 channel — traffic indistinguishable from legitimate AI tool usage on the network level.
- **AI middleware supply chain targeting:** TeamPCP/LiteLLM (March 2026) trojanized the LiteLLM PyPI proxy library, harvesting AI API keys and system prompts. The attack target was AI infrastructure itself, not AI as an offensive weapon — a structurally distinct threat category.

The detection implication across all three sub-patterns: malware that queries AI APIs embeds identifiable key patterns and prompt structures; behavioral profiling of AI API egress is required in addition to traditional IOC-based detection.

---

### Stage 7: Likely Next Stage (2026–2028)
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

1. **AI supply chain attacks become a primary threat vector.** The TeamPCP/LiteLLM case is the proof-of-concept. As enterprise AI adoption grows (every major application now integrates AI APIs), the libraries and proxy layers connecting enterprises to LLMs become high-value targets. Expect repeated supply chain compromises of PyPI/npm AI packages; expect AI API key harvesting to become a standard post-exploitation step alongside traditional credential theft. Defenders who have not inventoried their AI dependencies and pinned package versions are highly exposed. **[Confidence: HIGH]**

2. **LLM-querying malware goes mainstream.** The LAMEHUG/PROMPTSTEAL model will be adopted by additional threat actors beyond APT28. Expect to see criminal groups (not just nation-states) deploying malware with embedded AI API calls. Detection tooling will lag adoption by 6–12 months. **[Confidence: HIGH]**

3. **Deepfake video fraud scales significantly.** The technical barrier for multi-person real-time deepfake video (the Arup attack vector) continues to fall. Expect this attack to move from isolated high-value corporate targets to broader financial sector deployment. Average deal size will likely decrease as tooling becomes more accessible. **[Confidence: HIGH]**

4. **AI-enhanced vishing as default criminal TTP.** The 442% vishing increase documented in 2024 will continue. Voice cloning will become standard equipment for BEC actors and call-center fraud operations, not a specialized capability. **[Confidence: HIGH]**

5. **Agentic intrusion adoption by additional state actors.** GTG-1002 demonstrated the model. Other Chinese clusters and potentially DPRK/Iranian groups will attempt to replicate or acquire similar agentic tooling. Expect 2–4 additional primary-sourced agentic intrusion cases in this period. **[Confidence: MEDIUM]**

6. **Prompt injection against AI-integrated enterprise systems.** CrowdStrike documented 90+ organizations compromised via malicious prompt injection in 2025. This attack surface will expand in proportion to enterprise AI adoption. **[Confidence: MEDIUM]**

**High-risk use cases:**
- Financial sector: deepfake-enabled wire transfer authorization bypass
- Healthcare: AI-generated patient records / insurance fraud
- Government: AI-assisted identity fraud for security clearance applications

**Highest-confidence near-term escalation:** AI voice cloning in BEC (HIGH), LLM-querying malware adoption (HIGH), prompt injection against enterprise AI (MEDIUM).

---

### 10.2 3-Year Forecast (to 2029)

**Most likely trajectory:**

1. **AI-driven vulnerability discovery becomes offensive.** The Google Big Sleep model (autonomous zero-day discovery) will be applied offensively. Well-resourced state actors (China, Russia, DPRK) will run AI systems against public code repositories and binary patches to identify exploitable vulnerabilities before vendors issue patches. This represents the highest-risk AI capability shift in this timeframe. **[Confidence: MEDIUM]**

2. **Automated intrusion campaigns at scale.** Human-to-AI ratio in intrusion operations continues to decrease. A small team of 3–5 operators orchestrating dozens of simultaneous AI-agent intrusion campaigns becomes plausible. Current constraints (LLM hallucination, human oversight requirements) will partially resolve with model improvements. **[Confidence: MEDIUM]**

3. **Deepfake-enabled biometric authentication bypass.** Real-time AI bypass of facial recognition and voice authentication used in banking KYC and access control. FinCEN's 2024 alert on deepfake fraud in financial institutions marks the beginning of this threat arc; by 2029, this is on track to become a well-documented and frequently employed attack vector given the current adoption trajectory. **[Confidence: HIGH]**

4. **Criminal AI tool ecosystem matures.** Unlike 2023's largely vaporware underground LLMs, the 2027–2028 period will see functional criminal AI tooling — built on open-source model fine-tuning and uncensored model hosting, not on misleading advertisements. **[Confidence: MEDIUM]**

5. **AI for ICS/OT targeting.** CyberAv3ngers' 2024 ICS/SCADA research using ChatGPT is the early signal. By 2028, AI-assisted analysis of operational technology vulnerabilities will be a documented TTP for state-linked actors with ICS targeting mandates. **[Confidence: MEDIUM]**

**What defenders are underestimating:**
- The speed at which agentic AI intrusion will scale once the model is proven.
- The authentication threat from deepfakes — current enterprise MFA and call-back procedures assume real-time voice is trustworthy.
- The shift from AI-developed malware to AI-executed malware — detection logic designed for the former will be materially less effective against the latter without behavioral and egress-analysis layers.

---

### 10.3 5-Year Outlook (to 2031) — Low Confidence

> **Scope note:** Beyond a 24-month horizon in AI capability development, uncertainty is high. The items below represent directional projections, not forecasts. Treat with LOW confidence unless stated otherwise.

- **Intrusion automation deepens:** Human-to-AI decision ratio likely reaches 1–2 per campaign vs. 4–6 today, contingent on LLM hallucination rates improving and agentic frameworks maturing.
- **Signature evasion pressure escalates:** If PROMPTFLUX-model designs operationalize, signature-based detection faces structural erosion. AI-native detection investment becomes a prerequisite, not an option.
- **Deepfake-as-a-service commoditizes:** Real-time deepfake generation available as a pay-per-fraud service by 2028–2030 is the most analytically defensible 5-year projection. **[Confidence: HIGH]**
- **What is unlikely:** A single autonomous AI attack causing critical infrastructure failure. ICS compromise requires domain-specific knowledge and physical-cyber planning that current AI capability does not supply.

---

## 11. Final Conclusions

**Five conclusions supported by the weight of primary evidence:**

**1. Late 2025 is the strongest candidate for a qualitative inflection point in the public record.** Prior years saw AI enhancing existing TTPs. 2025 produced the first primary-sourced in-the-wild LLM-querying malware (LAMEHUG / PROMPTSTEAL), first AI-driven self-rewriting malware in development (PROMPTFLUX), and the most detailed provider disclosure of an agentic intrusion campaign (GTG-1002/GTG-2002). The threat model shifted qualitatively — though PROMPTFLUX remains development-phase and GTG-1002 autonomy claims are disputed, the directional change is clear.

**2. Social engineering and fraud remain the highest-impact AI use cases.** Not because intrusion use cases are unimportant, but because the earliest, most consistent, highest-dollar-loss applications of AI in attacks are in fraud and social engineering. The Arup case ($25M) and UAE bank case ($35M) dwarf any documented AI-assisted intrusion impact. Organizations investing AI threat budgets in intrusion detection while underinvesting in fraud controls and call verification procedures are misallocating resources.

**3. AI lowers barriers more than it creates superweapons.** The dominant effect of AI adoption by attackers is scale and accessibility — more actors doing existing attacks more efficiently — not the creation of capabilities that didn't exist before. The scale effect is dangerous in aggregate (higher phishing volume, more vishing operators, broader IO coverage) even when individual AI-enabled attacks are not qualitatively more sophisticated.

**4. LLM hallucination is an attacker constraint, not just a defender worry.** GTG-1002 demonstrated that AI agents make mistakes during live operations — they fabricate findings, misidentify data, and require human correction. This buys defenders time but does not make AI-driven attacks benign.

**5. The detection gap is real and widening.** Organizations designed to detect human-operated intrusions will struggle against agentic AI intrusions. Organizations relying solely on signature-based detection face increasing pressure against AI-assisted evasion — and will face further erosion if designs like PROMPTFLUX operationalize at scale. Organizations relying on voice call-back verification as a sole control will be exposed against real-time voice deepfakes. Detection infrastructure built for the pre-AI threat model requires re-examination against the 2025 threat model.

---

## 12. Top 10 Milestones Table

> **Table note:** Row 1 (DARPA CGC / Mayhem) is a defensive research milestone, not a threat-actor use event. It is included because it established the first publicly validated closed-loop automated vulnerability discovery pipeline — the architectural template for subsequent offensive AI development. Rows 7 and 10 are scoped as noted.

| # | Date | Milestone | Type | Evidence Quality |
|---|------|-----------|------|-----------------|
| 1 | August 2016 | DARPA Cyber Grand Challenge (Mayhem) — First publicly validated fully automated vulnerability discovery and exploit generation system in a controlled competition [RESEARCH PRECURSOR, not threat-actor use] | Research | PRIMARY |
| 2 | March 2019 | Earliest publicly documented primary-sourced criminal AI deployment: UK CEO voice cloning fraud (€220K) | Adversary | PRIMARY |
| 3 | January 2020 | First documented large-scale AI voice cloning fraud (in primary sources reviewed here): UAE bank ($35M) | Adversary | SECONDARY (court basis) |
| 4 | November 2022 | ChatGPT launch — LLM democratization; jailbreaking starts within days | Structural event | — |
| 5 | January 2024 | Arup CFO deepfake fraud ($25.6M) — multi-person real-time deepfake video conference deployed against corporate finance | Adversary | PRIMARY |
| 6 | February 14, 2024 | OpenAI/Microsoft joint disclosure: five nation-state APTs confirmed using LLMs | Disclosure | PRIMARY |
| 7 | July 2025 | LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) — first publicly documented in-the-wild malware querying an LLM at execution time (APT28, assessed exploratory phase) | Adversary | PRIMARY |
| 8 | August 2025 | GTG-2002 — Anthropic-disclosed case of agentic AI used for scaled data extortion across 17 organisations | Adversary | PRIMARY |
| 9 | November 2025 | SesameOp — first publicly documented abuse of a legitimate commercial AI API (OpenAI Assistants) as a covert C2 relay | Adversary | PRIMARY |
| 10 | March 2026 | TeamPCP/LiteLLM — first major confirmed attack targeting AI proxy middleware (supply chain, not AI used offensively); CVE-2026-33634 CVSS4 9.4 [ADJACENT CATEGORY] | Adjacent / AI infrastructure targeted | PRIMARY |

---

## 13. Top 10 Incidents Table

> **Sorting methodology:** Ranked by **analytical significance** — a composite of financial/operational impact, evidence quality, and novelty of AI use. Incidents with the highest primary-sourced losses and clearest AI component are ranked highest regardless of date. Chronologically descending order would favour recency over significance; this table prioritises what each incident contributed to understanding the AI threat landscape. Date column retains the actual incident date for reference.
>
> **Category note:** Row 3 (TeamPCP/LiteLLM) is an adjacent-category event: AI infrastructure was the target, not the weapon. It is included because it establishes a new threat category (AI supply chain) of direct relevance to defenders. Its ranking reflects novelty and potential blast radius, not direct harm caused by AI being used offensively.

| # | Date | Incident | Loss / Impact | AI Component | Sector | Source |
|---|------|----------|--------------|-------------|--------|--------|
| 1 | Jan 2024 | Arup CFO deepfake fraud | $25.6M | Multi-person real-time deepfake video conference | Professional services | PRIMARY |
| 2 | Jan 2020 | UAE bank voice cloning fraud | $35M | Voice cloning of company director | Financial | SECONDARY (court basis) |
| 3 | Mar 2026 | TeamPCP / LiteLLM supply chain attack | ~36% installation footprint (Wiz telemetry); 3–5 hr malicious window; SSH keys, cloud tokens, K8s secrets, API credentials exfiltrated; CVE-2026-33634 CVSS4 9.4 | AI supply chain compromise (no AI used offensively) | Enterprise SaaS, AI developers | PRIMARY |
| 4 | Jul–Aug 2025 | GTG-2002 agentic data extortion (17 orgs) | Ransom demands >$500K per victim; government, healthcare, emergency services targets | Claude Code as autonomous extortion operator | Government, healthcare, emergency | PRIMARY (Anthropic) |
| 5 | 2021–2024 | FAMOUS CHOLLIMA IT worker scheme | 320+ companies infiltrated; millions in fraudulent wages + insider access | AI-generated identities, face-swap, deepfake ID documents | Technology, government | PRIMARY (DOJ, FBI) |
| 6 | Jul 2025 | LAMEHUG (CERT-UA) / PROMPTSTEAL (GTIG) malware campaign (APT28) | Espionage; Ukraine government targets | LLM-querying malware generating system commands at runtime | Government / Ukraine | PRIMARY (CERT-UA) |
| 7 | Nov 2025 | GTG-1002 agentic espionage (~30 targets) | Espionage across tech, finance, government | Full intrusion lifecycle; 80–90% AI autonomy (disputed) | Technology, finance, government | PRIMARY (Anthropic) |
| 8 | Nov 2025 | SesameOp (AI API as covert C2) | Espionage persistence; scope undisclosed | OpenAI Assistants API abused as command relay | Single environment (public) | PRIMARY (Microsoft) |
| 9 | 2024 | APT42 AI-enabled operations (Iran) | Espionage | AI across full attack lifecycle: recon, phishing, malware development | Multiple sectors | PRIMARY (Google GTIG) |
| 10 | Mar 2019 | UK energy company CEO fraud | $243K | AI voice synthesis of German CEO | Energy | PRIMARY (insurer) |

---

## 14. Defender Recommendations

Based on the documented threat landscape, organized by priority:

**Immediate (within 90 days):**

1. **Implement out-of-band verification for all financial wire transfers and authorization requests received via voice or video.** A callback to a pre-registered number using a separate channel is the single most effective control against deepfake CEO/CFO fraud. Voice and video confirmation is no longer sufficient as a sole authorization mechanism.

2. **Audit your organization's AI API egress traffic and build detection baselines now.** LLM-querying malware (LAMEHUG model) generates outbound HTTPS to AI provider APIs from non-AI workloads. A practical first control: create a SIEM rule alerting on outbound connections to `api-inference.huggingface.co`, `api.openai.com`, `generativelanguage.googleapis.com`, or `dashscope.aliyuncs.com` originating from endpoints not in your approved AI tooling inventory. Any such connection from a standard Windows workstation or server is high-confidence suspicious. Expand to include the Anthropic and Alibaba Cloud AI API endpoints as the LAMEHUG pattern spreads beyond APT28.

3. **Run a phishing simulation using AI-generated content.** Test whether your organization's current phishing training prepares employees to recognize AI-generated content — which lacks traditional grammar/spelling signals. Update training if click-through rates exceed organizational benchmarks.

4. **Update identity verification procedures for remote workers and vendors.** AI-generated photos and face-swap technology defeat static image-based KYC. Implement liveness detection and multi-step verification. Cross-reference with government identity databases where available.

**Medium-term (3–12 months):**

5. **Deploy AI-native detection tooling.** Signature-based AV/EDR alone will be insufficient against PROMPTFLUX-model malware if such designs operationalize at scale. Behavioral detection, network traffic analysis, and anomaly-based approaches are required as complementary layers. Evaluate vendors specifically on their capability against LLM-querying and self-modifying malware.

6. **Map your attack surface for agentic AI exposure.** If your organization uses AI code assistants, agentic AI platforms, or API-connected AI services, assess whether an attacker could abuse these (via prompt injection, stolen API keys, or compromised AI-adjacent systems) to gain access or escalate privileges.

7. **Transition to FIDO2/hardware security keys for privileged accounts and high-value authorization flows.** Voice-based MFA and video-based identity verification are vulnerable to real-time AI voice/video synthesis. FIDO2-compliant hardware keys (YubiKey, Google Titan) are immune to voice and video deepfake replay because authentication is cryptographic and device-bound — an attacker who synthesizes your CFO's voice gains nothing against FIDO2. Treat any authorization flow that currently accepts a voice confirmation as a gap requiring hardware-key replacement.

8. **Monitor underground AI tool markets and AI provider threat intelligence disclosures.** OpenAI, Google GTIG, Anthropic, and Microsoft regularly publish threat intelligence reports on state-actor and criminal AI abuse. Align threat intelligence feed coverage to include these disclosures.

9. **Audit and pin all AI-related dependencies.** The TeamPCP/LiteLLM case demonstrates that AI proxy libraries are high-value supply chain targets. Pin all AI-related Python/npm packages to exact versions using cryptographic hashes in lockfiles. Disable automatic mutable version updates for AI middleware. Treat AI dependencies (LiteLLM, LangChain, LlamaIndex, etc.) with the same supply chain scrutiny as security-critical libraries.

10. **Inventory AI API credentials as privileged secrets.** AI API keys grant access to everything your enterprise sends to an AI provider — including sensitive business data and system prompts containing proprietary logic. Store AI API keys in secrets managers (not hardcoded, not in environment files). Rotate regularly. Monitor for credential exfiltration via SIEM rules covering API key patterns in egress data.

**Strategic (12+ months):**

11. **Assume agentic AI intrusion as part of your threat model.** Design detection strategies that account for intrusion campaigns conducted predominantly by AI agents — not by human operators following predictable human behavioral patterns. AI-driven intrusions may move faster, operate at unusual hours, and generate traffic patterns inconsistent with human operation.

12. **Develop AI-specific incident response procedures.** A SOC designed to analyze human-operated intrusions needs adaptation for AI-operated ones. Key differences: AI agents may generate higher-volume, lower-dwell-time lateral movement; AI hallucination may produce unusual artifacts (fabricated log entries, overstated access claims); AI-generated phishing and social engineering require different victim communication and training responses.

13. **Engage with AI provider abuse reporting mechanisms.** OpenAI, Anthropic, and Google all operate threat intelligence programs and accept reports of suspected malicious AI usage. If you identify LLM API calls in malware or suspect an AI system is being used against your organization, these providers have disruption capabilities (account termination, key invalidation) that can degrade ongoing campaigns.

---

## 15. Source Register

> **Citation architecture note:** Inline `[Rn]` markers in the report body refer to the row numbers below. Where a URL is not present in the original source document provided for this review, the entry is marked `[link not available in provided draft]`; this does not imply the source is unverifiable — only that a URL was not included in the draft text reviewed.

| # | Source | Type | Quality | Key Findings Used | Link/DOI |
|---|--------|------|---------|------------------|----------|
| R1 | OpenAI/Microsoft "Disrupting Malicious Uses of AI by State-Affiliated Threat Actors" (Feb 14, 2024) | Joint official disclosure | PRIMARY | Five APT groups using LLMs; assessed as exploratory | [link not available in provided draft] |
| R2 | OpenAI "Disrupting Deceptive Uses of AI by Covert Influence Operations" (May 30, 2024) | Official report | PRIMARY | Five IO operations disrupted; none built real audience | [link not available in provided draft] |
| R3 | OpenAI "Influence and Cyber Operations: An Update" (October 9, 2024) | Official report | PRIMARY | 20+ operations disrupted; SweetSpecter, CyberAv3ngers, Storm-0817 | [link not available in provided draft] |
| R4 | OpenAI Threat Intelligence Report (February 21, 2025) | Official report | PRIMARY | Romance scam networks; Chinese IO targeting Japan | [link not available in provided draft] |
| R5 | Microsoft Digital Defense Report 2023 (October 2023) | Official report | PRIMARY | AI for phishing, IO; attack volume statistics | [link not available in provided draft] |
| R6 | Microsoft Digital Defense Report 2024 (October 2024) | Official report | PRIMARY | 600M daily password attacks; AI IO use by Iran | [link not available in provided draft] |
| R7 | NCSC UK "Near-Term Impact of AI on Cyber Threat" (January 24, 2024) | Government assessment | PRIMARY | "Almost certainly" increases attack volume; barrier to entry | [link not available in provided draft] |
| R8 | NCSC UK "Impact of AI on Cyber Threat to 2027" (2025) | Government assessment | PRIMARY | Enhancement not novel TTPs; full autonomy unlikely before 2027 | [link not available in provided draft] |
| R9 | Google GTIG "Adversarial Misuse of Generative AI" (January 2025) | Vendor primary research | PRIMARY | 40+ APTs on Gemini; APT42 broadest documented state-actor AI use; DPRK most prolific in IT worker AI | [link not available in provided draft] |
| R10 | Google GTIG AI Threat Tracker (November 2025) | Vendor primary research | PRIMARY | LAMEHUG, PROMPTFLUX, PROMPTSTEAL; 5+ in-wild LLM malware families documented | [link not available in provided draft] |
| R11 | Google Project Zero "Big Sleep" blog (published November 1, 2024; discovery October 2024) | Primary research blog | PRIMARY | AI autonomous zero-day in production software: stack buffer underflow in SQLite `seriesBestIndex`, dev branch only, no CVE. **Distinct from CVE-2025-6965** (July 2025, integer truncation, production release) | https://projectzero.google/2024/10/from-naptime-to-big-sleep.html |
| R12 | CERT-UA Advisory (July 17, 2025) | Government advisory | PRIMARY | LAMEHUG attribution to APT28; Qwen 2.5-Coder API querying at runtime | [link not available in provided draft] |
| R13 | Anthropic Report on GTG-1002 (November 13, 2025) | Company official report | PRIMARY | High-autonomy AI-assisted intrusion; 80–90% AI autonomy (provider claim; disputed by peer analysts); ~30 targets | [link not available in provided draft] |
| R14 | CrowdStrike Global Threat Report 2025 | Vendor primary report | PRIMARY | 442% vishing increase H1→H2 2024; FAMOUS CHOLLIMA 320+ infiltrations; DPRK 220% YoY growth | [link not available in provided draft] |
| R15 | CrowdStrike Global Threat Report 2026 | Vendor primary report | PRIMARY | 89% increase AI-enabled adversaries; prompt injection at 90+ orgs; 29-min avg eCrime breakout | [link not available in provided draft] |
| R16 | FBI IC3 2024 Internet Crime Report | Government primary | PRIMARY | $16.6B total losses; BEC $2.77B; crypto $9.3B | [link not available in provided draft] |
| R17 | FinCEN Deepfake Fraud Alert (November 2024) | Government advisory | PRIMARY | SAR increase for deepfake fraud since 2023; systemic threat to financial sector | [link not available in provided draft] |
| R18 | CISA Advisory AA23-320A (Scattered Spider, November 2023) | Government advisory | PRIMARY | MGM breach; vishing methodology; AI voice not confirmed in 2023 attack | [link not available in provided draft] |
| R19 | DOJ DPRK IT Worker Indictment (December 2024) | Court/legal document | PRIMARY | 80+ US identities; 100+ companies; AI-generated profiles confirmed | [link not available in provided draft] |
| R20 | KnowBe4 DPRK worker disclosure (July 2024) | Company disclosure | PRIMARY | AI-generated profile photo; face-swap on identity document; automated KYC bypass | [link not available in provided draft] |
| R21 | Euler Hermes statement on 2019 CEO fraud | Insurer primary witness | PRIMARY | Earliest documented criminal voice cloning in this review; €220K; first cybercrime with AI per insurer | [link not available in provided draft] |
| R22 | Arup official statement + Hong Kong Police confirmation (May 2024) | Company + government | PRIMARY | $25.6M deepfake CFO fraud; 15 wire transfers; multi-person real-time video deepfake | [link not available in provided draft] |
| R23 | Trend Micro "The Reality Behind AI Threats" (August 2023) | Vendor primary research | PRIMARY | WormGPT/FraudGPT capabilities NOT independently verified; only promotional material found | [link not available in provided draft] |
| R24 | SentinelOne LABScon 2025 presentation | Vendor primary research | PRIMARY | 7,000+ samples with embedded AI API keys (retrohunt on VirusTotal); "almost all turned out to be non-malicious" per primary report; 6,000+ unique keys; LAMEHUG/PROMPTSTEAL confirmed malicious subset (284 HuggingFace keys); MalTerminal earliest known LLM-enabled malware sample (PoC, pre-Nov 2023) | [link not available in provided draft] |
| R25 | IBM X-Force Threat Intelligence Index 2024 | Vendor primary report | PRIMARY | No concrete evidence of GenAI-engineered attacks in 2023–2024 | [link not available in provided draft] |
| R26 | Europol EU-SOCTA 2025 | Government/agency | PRIMARY | AI "fundamentally reshaping organized crime"; multilingual victim targeting | [link not available in provided draft] |
| R27 | Seymour & Tully, "Weaponizing Data Science for Social Engineering: Automated E2E Spear Phishing on Twitter" (SNAP_R) | Black Hat USA 2016 / ZeroFOX | PRIMARY (research precursor) | LSTM and Markov generation modes; 30–66% CTR; 6.85 tweets/min; 819 targets over 2-hour bake-off | https://www.blackhat.com/docs/us-16/materials/us-16-Seymour-Tully-Weaponizing-Data-Science-For-Social-Engineering-Automated-E2E-Spear-Phishing-On-Twitter.pdf |
| R28 | Brumley et al., "Hacking as a Service: The Business of Vulnerability Discovery" / CGC Mayhem documentation; "Mayhem: The DARPA Cyber Grand Challenge Winning System" | IEEE Security & Privacy / ForAllSecure (CMU) | PRIMARY (research precursor) | Fully automated vulnerability discovery and exploitation pipeline; symbolic execution + concolic fuzzing; CGC Final Event August 4, 2016 | DOI: 10.1109/MSEC.2017.2759104 |
| R29 | Kirat, Jang & Stoecklin, "DeepLocker: How AI Can Power a Stealthy New Breed of Malware" | IBM Research / Black Hat USA 2018 Briefings | PRIMARY (research precursor) | CNN (AlexNet referenced in slides) as cryptographic trigger for payload decryption; payload unrecoverable without biometric trigger | https://securityintelligence.com/deeplocker-how-ai-can-power-a-stealthy-new-breed-of-malware/ |
| R30 | Takaesu (MBSD), "DeepExploit: Fully Automated Penetration Test Tool using Machine Learning" | Black Hat Arsenal 2018 / MBSD | PRIMARY (research precursor) | A3C RL agent orchestrating Metasploit RPC API; reward-shaped policy on shell-session success; GitHub: github.com/13o-bbr-bbq/machine_learning_security/tree/master/DeepExploit | https://www.blackhat.com/us-18/arsenal/schedule/#deep-exploit-11908 |
| R31 | Fang et al., "LLM Agents can Autonomously Exploit One-day Vulnerabilities" (arXiv 2404.08144, April 2024) | Academic (UIUC) | SECONDARY | 87% CVE exploitation rate with description; 7% without | https://arxiv.org/abs/2404.08144 |
| R32 | UAE $35M voice cloning fraud (publicly disclosed October 2021) | Court documents via media | SECONDARY (court basis) | $35M loss; at least 17 individuals identified in UAE investigation | [link not available in provided draft] |
| R33 | Vade Security Q4 2022 Phishing Report | Vendor quarterly | SECONDARY | 274% Q3→Q4 2022 phishing surge post-ChatGPT launch (causal link probable but unproven) | [link not available in provided draft] |
| R34 | Hoxhunt phishing effectiveness research (2025) | Vendor research | SECONDARY | AI surpassed human red team in phishing effectiveness (Feb–Mar 2025); 5-min AI campaign generation vs. 16-hr human red team. CTR figures from Hoxhunt are 2–4%; 54% CTR belongs to Heiding et al. [R47], not Hoxhunt | [link not available in provided draft] |
| R35 | KELA Intelligence underground forum data (2024) | Vendor research | SECONDARY | 219% dark web AI tool mentions increase; 52% rise in AI jailbreak discussions | [link not available in provided draft] |
| R36 | SlashNext 1,265% phishing surge claim | Single vendor claim | WEAK | Cited for context only; methodology unclear; do not cite as authoritative | [link not available in provided draft] |
| R37 | WormGPT/FraudGPT marketing claims (underground forums, 2023) | Underground advertisements | WEAK | No functional capability independently verified; no confirmed deployment | [link not available in provided draft] |
| R38 | OpenAI June 2025 threat report (ScopeCreep, DPRK IT workers) | Official report | PRIMARY | ScopeCreep LLM-assisted Windows malware development; DPRK job-application automation at scale | [link not available in provided draft] |
| R39 | Anthropic August 2025 report (GTG-2002) | Official report | PRIMARY | Agentic extortion; Claude Code as autonomous operator across 17 organisations in one month; ransom demands >$500K | [link not available in provided draft] |
| R40 | Microsoft incident response report, November 2025 (SesameOp) | Primary vendor IR | PRIMARY | OpenAI Assistants API abused as covert C2 relay; traffic indistinguishable from legitimate AI usage | [link not available in provided draft] |
| R41 | Wiz, Snyk, Datadog Security Labs, Endor Labs, FutureSearch, Kaspersky, BleepingComputer, LiteLLM official advisory (TeamPCP / LiteLLM, March 2026) | Multi-vendor primary | PRIMARY | AI supply chain attack; ~36% cloud environment installation footprint (Wiz telemetry); 3–5 hr malicious window; credential harvester + K8s toolkit + systemd backdoor; CVE-2026-33634, CVSS4 9.4 | [link not available in provided draft] |
| R42 | Mandiant M-Trends 2026 | Primary vendor report | PRIMARY | Voice phishing 11% of initial infection vectors in 2025 investigations (up from lower baseline); email phishing declined to 6% | [link not available in provided draft] |
| R43 | Microsoft Digital Defense Report 2025 | Official report | PRIMARY | $4B fraud blocked Apr 2024–Apr 2025; 1.6M fake account creation attempts/hr; AI-generated ID growth 195% | [link not available in provided draft] |
| R44 | FBI IC3 Annual Report 2025 | Government primary | PRIMARY | 22,364 AI-related complaints; $893M adjusted losses; $632M from investment scams with AI nexus; $30.3M BEC with AI nexus | [link not available in provided draft] |
| R45 | FBI IC3 PSA (December 19, 2025) | Government advisory | PRIMARY | AI voice cloning used to impersonate senior US officials since at least 2023; targets include government and military | [link not available in provided draft] |
| R46 | Singapore Cyber Security Agency, "Singapore Cyber Landscape 2023" (July 30, 2024) | Government primary | PRIMARY | ~13% of 40 sampled phishing emails contained AI-generated content (caveated: imperfect detection tools, small sample) | [link not available in provided draft] |
| R47 | Heiding, Schneier et al., "Devising and Detecting Phishing: Large Language Models vs. Smaller Human Models" (arXiv:2412.00586, submitted November 30, 2024) — **arXiv preprint, not peer-reviewed at time of writing** | Academic preprint | SECONDARY | AI-automated phishing: 54% CTR vs. 12% control (101 participants, controlled study); AI + minimal human-in-loop: 56% CTR. This 54% figure is attributable to this study, not to Hoxhunt | https://arxiv.org/abs/2412.00586 |

---

*Evidence cutoff: April 2026. All citations reference publicly available documents as of this date. Classification: Open source / Unclassified.*

*For corrections, additional sourcing, or technical questions: [Medium @1200km](https://medium.com/@1200km)*
