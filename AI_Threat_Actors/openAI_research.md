
Evolution of AI Usage by Threat Actors in Cyber Operations and Fraud
Executive summary and key judgments
This report synthesises verifiable public reporting (vendor threat intelligence, government/CERT advisories, court/LE reporting where available, and peer‑reviewed/academic work) on how threat actors have incorporated AI into real-world operations from the earliest verifiable AI-enabled attacks to April 2026. 

Key judgments (with confidence)

AI’s most measurable operational impact so far is on social engineering at scale (phishing, vishing, impersonation, translation, and persona building), primarily by reducing cost/friction and improving linguistic plausibility. High confidence. Evidence: controlled human-subject phishing study showing LLM-generated spear-phishing performance on par with human experts, dramatically outperforming baseline phishing; multiple government/vendored assessments and metrics on voice/phishing growth. 
Deepfake-enabled fraud has moved from “novel” to “repeatable playbook” in high-value corporate payment contexts (e.g., fake executive video conferences) and in government/financial impersonation scams. High confidence for existence; Medium confidence for prevalence and aggregate global loss size because consistent global accounting remains immature. 
2025 marks the clearest inflection point from AI-as-assistant to AI embedded in tooling, including (a) malware querying LLMs during execution and (b) agentic orchestration frameworks for intrusion tasks. Medium-to-high confidence (strongest evidence from vendor AI providers’ threat reports and GTIG). 
“Fully autonomous hacking in the wild” remains rare, but credible documentation exists of high-autonomy operations where AI executed most tactical steps under human strategic supervision. Medium confidence because visibility is constrained to a subset of platforms/providers, and independent corroboration is limited. 
Most observed AI use still improves existing TTPs rather than introducing fundamentally new ones, aligning with government and major vendor assessments (notably in 2024–2025), though “AI-in-the-loop malware” and “LLM-as-C2/service brain” are emerging exceptions. High confidence. 
Over the next 12–36 months, the highest-risk trajectories are interactive, identity-centric attacks (voice/video social engineering and insider-style access acquisition) plus runtime-adaptive malware, constrained by API access, cost, and reliability—but likely to diffuse through “as-a-service” markets. Medium confidence. 
Chronological evolution and milestone timeline
Evidence grading used in this timeline
Confirmed: primary disclosure (CERT/government advisory, AI provider threat report, or major vendor report) clearly describing AI use in an operation or tooling chain.
Credible reported: reputable secondary reporting with specific details, but limited technical corroboration or incomplete attribution.
Suspected / unverified: plausible claims lacking sufficient detail, corroboration, or primary documentation.
Earliest verifiable documented AI-enabled attack found
The earliest verifiable publicly documented AI-enabled attack/fraud identified in this research is a March 2019 (reported September 2019) CEO-voice deepfake used to authorise a fraudulent transfer (~€220k / ~$243k). The reporting describes AI-generated voice imitation used in a payment redirection scenario. 

Timeline of notable milestones
Date (exact when available)	Actor / group (if known)	Country context	Attack type	Exact AI usage	Evidence level	Significance
Mar 2019 (reported 5 Sep 2019)	Unknown criminals (victim: unnamed firm)	United Kingdom / Germany / Hungary	Payment fraud / BEC-style vishing	Voice deepfake to impersonate CEO and pressure urgent transfer (~€220k / ~$243k).	Confirmed (credible vendor write-up citing insurer/WSJ reporting)	Often cited as first widely documented corporate voice deepfake fraud case. 
Mar 2023 (trend marker)	Underground ecosystem	Global	Capability diffusion (crimeware market)	“Criminal LLM” branding (e.g., WormGPT) begins proliferating; later assessed as commonly wrappers/jailbreaks rather than true sovereign models.	Confirmed (major threat research vendor)	Start of recognisable “LLM-as-a-service” criminal marketing wave. 
5 Jun 2023	Unknown criminals	United States	Harassment/extortion enablement	FBI warns of AI-enabled synthetic media (“deepfakes”) used to target victims.	Confirmed (government PSA)	Early official signalling that cheap synthetic media is materially enabling abuse. 
24 Jan 2024	Assessment product (not an incident)	United Kingdom	Threat trend assessment	NCSC assesses AI will “almost certainly” increase attack volume/impact; uplift strongest in recon + social engineering; advanced autonomous uses unlikely before 2025.	Confirmed (government assessment)	Establishes a baseline: “evolution not revolution” near-term, with emphasis on social engineering. 
Feb 2024 (release 7 Feb 2024)	Unknown fraudsters	Hong Kong	Corporate payment fraud	Deepfake video conference impersonating executives; transfer HK$200m to five local accounts; reportedly built from public audio/video (e.g., online footage).	Confirmed (CERT bulletin citing police & case details)	First widely reported multi-person deepfake video meeting used for high-value corporate theft. 
14 Feb 2024	Multiple state-linked and criminal actors (observed activity)	Multi-country	Tradecraft augmentation	Joint Microsoft/OpenAI reporting: threat actors use LLMs mainly for productivity (recon, scripting, translation); no novel AI-enabled techniques observed at that time.	Confirmed (major vendor + partner report; corroborated by Reuters coverage)	Strong “reality check” milestone: AI as accelerator, not decisive new capability (in early 2024). 
8 May 2024	General criminal ecosystem	United States	Fraud/scams (warning)	FBI warns cybercriminals increasingly use AI for convincing voice/video and emails to facilitate fraud.	Confirmed (government field office advisory)	Signals expectation of broader diffusion into everyday scam workflows. 
30 Jul 2024 (publication date)	Multiple scam actors	Singapore	Phishing content at scale (observational study)	Singapore CSA: among 40 unique phishing email samples analysed, ~13% contained AI-generated content; CSA caveats detection tools are not perfect.	Confirmed (government report with uncertainty note)	One of the few official quantified indicators of AI-generated phishing content in a national dataset. 
5 Nov 2024 (published 3 Dec 2024)	Unknown criminals	United States	Financial fraud enablement (warning)	IC3 warns criminals use generative AI for financial fraud (deepfakes, social engineering).	Confirmed (IC3 PSA)	Reinforces that US law enforcement sees AI appearing inside fraud reporting streams. 
Jan 2025	Multiple state-linked actors	Multi-country	LLM misuse / augmentation	GTIG analysis of threat actors’ use of Gemini: common tasks (research, troubleshooting, content generation) with unsuccessful jailbreaks and no “game-changer” capabilities yet.	Confirmed (primary GTIG report)	Benchmarks early‑2025 reality: extensive experimentation, limited breakthrough capability. 
27 Feb 2025	Multiple eCrime and state actors (observed data)	Global	Social engineering scale	CrowdStrike reports 442% increase in vishing between H1 and H2 2024, attributing growth to AI-driven phishing/impersonation tactics; also highlights identity-based intrusions and access broker activity.	Confirmed (major vendor report release)	Quantitative indicator that interactive voice attacks are surging in the period when GenAI becomes mainstream. 
7 May 2025	Assessment product (not an incident)	United Kingdom	Threat trend assessment	NCSC projects to 2027: AI likely enhances vulnerability research/exploit development and evasion/scalability; fully automated end-to-end advanced attacks unlikely by 2027.	Confirmed (government assessment)	Provides an official medium-term baseline against which “autonomy” claims can be tested. 
Jun 2025 (report date)	Multiple clusters incl. suspected DPRK-linked IT worker schemes; PRC-linked APT infra; Russian-speaking malware developer	Multi-country	Multi‑use	OpenAI reports disruptions: deceptive IT-worker job fraud; malware dev (“ScopeCreep”); PRC-linked infra (APT5/apt15 labels) using models for technical research and script modification; scam translation workflows.	Confirmed (primary AI provider threat report)	Demonstrates cross-category AI use in real operations (fraud + malware + IO support). 
Jun–Jul 2025 (reported later)	APT28 attribution in reporting	Ukraine	Intrusion tooling evolution	GTIG identifies malware (PROMPTSTEAL / LAMEHUG) that queries an LLM at runtime via the Hugging Face API to generate commands; GTIG calls this the first observation of malware querying an LLM in live ops.	Confirmed (primary GTIG report)	First well-documented “LLM-in-the-loop malware” pattern in live operations (runtime command generation). 
Aug 2025	GTG-2002 (tracked by provider)	Multiple international targets	Data extortion at scale	Anthropic reports disruption of a data-extortion operation using Claude Code as an active operator, impacting at least 17 organisations in a month; ransom demands sometimes >$500k; AI supported multiple lifecycle phases.	Confirmed (primary AI provider report)	One of the clearest public cases of agentic coding tool use for scaled intrusion/extortion workflows. 
Mid-Sep 2025 (disclosed Nov 2025)	GTG-1002 (assessed China state-sponsored by provider)	~30 targeted entities	Cyber espionage	Anthropic reports “AI-orchestrated” intrusion campaign: AI executed ~80–90% of tactical work, humans supervised strategic gates; provider claims first documented case of a cyberattack largely executed without human intervention at scale (with noted hallucination limits).	Confirmed (primary AI provider report)	Strongest public claim of high-autonomy intrusion operations; still includes human oversight and meaningful reliability constraints. 
3 Nov 2025 (discovered Jul 2025)	Unknown espionage actor	Unspecified victim environment	Covert C2	Microsoft reports SesameOp backdoor using the OpenAI Assistants API for command-and-control (service-abuse C2 channel); OpenAI account/key disabled.	Confirmed (major vendor incident response report)	Landmark case of legitimate AI API abused as C2/relay, complicating detection and attribution. 
Nov 2025	Multiple actors	Global	Tooling evolution	GTIG reports multiple malware families with novel AI capabilities in 2025 (PROMPTFLUX, PROMPTSTEAL, QUIETVAULT, PROMPTLOCK PoC; plus other features), including self-modifying malware using LLM APIs.	Confirmed (primary GTIG report)	Consolidates the 2025 shift: AI embedded inside malware and credential theft workflows (some experimental, some operational). 
19 Dec 2025	Unknown actors	United States	Impersonation / influence / social engineering	IC3 warns of campaign impersonating senior US officials using AI-generated voice messages, stating activity “since at least 2023”.	Confirmed (IC3 PSA)	Official timeline evidence that AI voice cloning is operational in targeted impersonation campaigns. 
Jan 2026	Criminal ecosystem	Global	Underground market evolution	Trend Micro assesses “criminal AI” ecosystem has industrialised: consolidation around jailbreak-as-a-service, increased deepfake commoditisation; dynamic code-generation malware constrained by API revocation and unreliability.	Confirmed (major vendor research)	Strong evidence of professionalisation and commoditisation—plus realistic constraints on “AI malware” hype. 
Mar 2026	Cross-sector	Global	Strategic synthesis	Mandiant special report states 2025 saw shift from experimentation to operationalisation, noting adaptive malware (PROMPTFLUX/PROMPTSTEAL) and “agentic” evolution; emphasises governance gaps (“Shadow AI”).	Confirmed (major vendor report)	Provides a defender lens on AI risk: much risk is still foundational controls, but adversary capabilities are advancing. 
Mar–Apr 2026	Broad victim base	United States	National reporting statistics	FBI IC3 annual report for 2025: 22,364 AI-related complaints, $893M adjusted losses; investment scams with AI nexus $632M, BEC AI $30M.	Confirmed (government annual report)	Best available official quantitative baseline for AI-linked cyber-enabled crime in the US. 

Mermaid timeline (high-level)

2019
Voice deepfakeBEC-style fraud(CEO impersonation)
2023
Criminal LLMbranding + increaseddeepfake warnings
2024
Deepfakevideo-conferencefraud; “AI mostlyproductivity” vendorconsensus
2025
Embedded AI inmalware + agenticintrusion/extortiondisclosures
2026
National AI-crimestatistics emerge;marketindustrialisationevidence strengthens
AI use by threat actors: key inflection points


Show code
Major incidents and actor segmentation
Most important AI-enabled incidents
The table below prioritises incidents with (a) primary-source disclosure, (b) clear AI component, and (c) operational significance (impact, novelty, or evidence of diffusion). “Losses/impact” is reported where available; many intrusion-focused cases do not publish monetised impact figures.

Incident	Dates	Losses / impact (reported)	Sector / victims	AI component	Novelty vs “AI-improved TTP”	Primary sources
CEO voice deepfake payment fraud	Mar 2019 (reported Sep 2019)	~€220k / ~$243k transfer	Energy (unnamed firm)	Voice cloning / deepfake audio	AI-improved social engineering (vishing/BEC)	Sophos write-up citing insurer/WSJ reporting. 
Deepfake “executive video conference” payment fraud	Publicly described Feb 2024	HK$200m transferred to five local accounts	Multinational corporate victim	Deepfake video + voice impersonation	AI-improved exec impersonation with multi-party realism	HKCERT bulletin (police-described case). 
“ScopeCreep” malware development assisted by LLMs	Disclosed Jun 2025	Distribution observed; impact assessed limited in report	End users via trojanised software repo	LLM-assisted Windows malware dev/debug + infra setup	AI-improved malware engineering velocity	OpenAI June 2025 report. 
PRC-linked groups using LLMs for technical workflows (APT5/APT15 labels)	Disclosed Jun 2025	Disruption of accounts; operational impact unclear	Likely espionage/support activity	Script modification, troubleshooting configs, automation research	AI-improved recon + scripting + ops support	OpenAI June 2025 report. 
Deceptive employment “IT worker” schemes scaling with AI	Disclosed Jun 2025	Fraudulent hiring attempts; access-risk > direct $ loss	Enterprises hiring remote IT	Resume/persona generation, automation loops; remote work setup research	AI-improved identity/persistence tradecraft	OpenAI June 2025 report. 
LLM-querying malware in live ops (PROMPTSTEAL / LAMEHUG)	Identified Jun–Jul 2025; disclosed Nov 2025	Targeting Ukraine; impact not publicly monetised	Government/strategic targets	Runtime LLM queries to generate commands via external API	More novel: AI embedded mid-execution for command generation	GTIG report (with figures). 
Agentic data-extortion operation using coding agent	Disclosed Aug 2025	At least 17 organisations targeted in a month; ransom demands sometimes >$500k	Government, healthcare, emergency services, religious institutions	Claude Code as active operator across lifecycle	More novel: AI as operator, not only advisor	Anthropic August 2025 report. 
High-autonomy AI-orchestrated espionage campaign	Detected mid‑Sep 2025; disclosed Nov 2025	~30 entities targeted, handful of intrusions validated	Tech + government targets (not fully enumerated publicly)	Multi-agent orchestration; AI executed ~80–90% tactical tasks	Most novel: high autonomy with human strategic gates	Anthropic Nov 2025 report + architecture diagram. 
AI API abused as C2/relay (SesameOp)	Discovered Jul 2025; disclosed Nov 2025	Espionage-type persistence; scope undisclosed	Single victim environment (public)	Abuse of OpenAI Assistants API as C2/storage/relay	More novel: “legitimate AI service as C2”	Microsoft incident response report. 
AI-linked impersonation of senior officials (smishing/vishing)	Since at least 2023; PSAs 2025	Objective: access/scam/exfil; losses not aggregated	Government-linked targets and contacts	AI-generated voice messages for impersonation	AI-improved impersonation at scale	IC3 PSAs (May & Dec 2025). 

Actor segmentation: who is ahead and why
Financially motivated fraud and BEC-style crime is presently the category where AI creates the most repeatable advantage. Real-world high-value cases show deepfakes augmenting BEC/vishing playbooks (2019 voice deepfake; 2024 deepfake video meeting). 
 The FBI’s 2025 IC3 annual reporting also indicates that “AI-nexus” losses concentrate heavily in investment scams (>$600m) and include meaningful BEC losses (> $30m), suggesting wide diffusion in financially motivated crime. 

Ransomware operators appear to be benefiting mainly indirectly: AI improves initial access (better phishing/vishing, better language) and later-stage monetisation (data triage and extortion messaging), rather than generating a completely new ransomware model. This is consistent with the NCSC’s assessment that near-term uplift is strongest in social engineering and data analysis, and that fully automated end-to-end attacks are unlikely even to 2027. 
 However, “data extortion without encryption” campaigns using agentic tooling represent a practical operational variant that looks ransomware-adjacent (extort via stolen data rather than encryption). 

State-linked APT / espionage actors have clear incentives to apply AI to accelerate research, translation, and scripting—and credible 2025 disclosures show an evolution into higher autonomy or AI-embedded malware. 
 The strongest publicly documented “autonomy” claim to date comes from an AI provider’s internal misuse investigation, which may not generalise across all APT ecosystems but is nonetheless a meaningful milestone. 

Influence operations and propaganda networks benefit from generative text production, translation, and persona management. OpenAI’s reporting shows multiple influence or “covert IO” clusters using LLMs to generate posts/comments and persona assets, but it also frequently notes limited demonstrated real-world impact (e.g., limited authentic engagement). 

Hacktivists are plausibly uplifted (especially for recon, targeting lists, translation, and basic scripting), but high-quality public documentation of “AI-enabled hacktivist breakthroughs” is thinner than for fraud and state-linked activity. This aligns with the NCSC’s model: significant uplift “from a low base”, mainly through commoditised tools and improved social engineering. 

TTP analysis and technical evolution
This section uses an ATT&CK-style lifecycle lens. Confirmation levels vary by phase because some AI use is inherently difficult to observe externally (e.g., drafting prompts offline).

ATT&CK-style phase analysis of AI use
Phase	How AI is used	Confirmation level in the wild	Representative examples (non-exhaustive)	Constraints / limitations
Reconnaissance	OSINT summarisation, target research, vulnerability research, multilingual context building	High	Microsoft/OpenAI observed LLM use for recon/scripting/translation (early 2024). 
 GTIG observed broad use for research/troubleshooting (Jan 2025) and later multi-surface intrusion support (Nov 2025). 
Models rely on public info; hallucinations; OPSEC risk when using third-party services. 
Resource development	Persona generation, fake resumes, pretext scripts, domain/asset brainstorming; creating scam content at scale; potential automation around infra selection	High	OpenAI “IT worker” scheme: automated resume/persona generation and research into remote-work setups. 
 Microsoft (2026) describes threat actors operationalising AI for content/code/media and persona development. 
Quality still bounded by source data; human review often needed; defensive screening can catch inconsistencies. 
Initial access	More persuasive phishing; vishing; deepfake video/voice impersonation; lure localisation	High	Deepfake fraud case in Hong Kong. 
 CrowdStrike: vishing up 442% H1→H2 2024 as AI-driven impersonation rises. 
Requires victim interaction; mature orgs can enforce out-of-band verification; voice/video can still show artefacts. 
Social engineering/phishing	Natural language quality, personalisation, translation; automated profiling and message tailoring	High	Controlled study: AI-generated spearphish achieved click rates comparable to human experts (12% baseline vs ~54–56% for human/AI). 
 Singapore CSA: ~13% of sampled phishing emails contained AI-generated content (with caveats). 
“AI-written” detection imperfect; training & policy controls mitigate but are bypassed; scaling raises detection opportunities. 
Malware development	LLM-assisted coding, debugging, porting; creating obfuscation variants; building tooling faster	High	OpenAI “ScopeCreep” case: incremental improvements to Windows malware and C2 setup. 
 Trend Micro notes widespread underground interest in using LLMs to improve code (Aug 2023). 
Output quality varies; requires integration/testing; many actors still prefer proven tooling; provider controls can disrupt. 
Command and control	Abuse AI APIs as command relay; malware queries external LLMs (LLM-as-service “brain”)	Medium-to-high	Microsoft SesameOp used OpenAI Assistants API as C2/storage/relay. 
 GTIG PROMPTSTEAL uses Hugging Face API to generate runtime commands. 
API keys can be revoked; network controls can detect unusual API egress; reliance on third parties is brittle. 
Credential theft	AI helps generate commands for discovery/collection; prompts search local secrets; supports targeted data mining	Medium-to-high	GTIG: PROMPTSTEAL generates commands for theft; QUIETVAULT uses AI prompts & on-host AI CLI tools to find secrets. 
Still needs foothold; “secrets hunting” can be noisy; modern secrets management reduces payoff. 
Defence evasion	LLM-assisted obfuscation; self-modifying scripts; “prompts as code” to evade LLM-powered detection; blending into identity/cloud activity	Medium-to-high	GTIG: PROMPTFLUX prompts Gemini to rewrite/obfuscate itself; FRUITSHELL contains detection-bypass prompts. 
 Trend Micro: dynamic AI code-gen limited operationally but emerging. 
Unpredictability; token/key revocation; behavioural detections can still catch. 
Persistence	AI helps craft persistence scripts; can regenerate variants; supports long-term “inside” activity (e.g., insider-style schemes)	Medium	GTIG: PROMPTFLUX saves regenerated versions into Startup for persistence. 
 AI-enabled IT worker schemes aim for durable access. 
Requires initial foothold; persistence often detectable via standard controls and monitoring. 
Privilege escalation	AI suggests or generates code paths; helps troubleshoot exploits and privilege logic	Medium	OpenAI “ScopeCreep” mentions privilege escalation features; Anthropic reports escalation guidance in operations. 
High dependence on environment-specific conditions; LLM hallucination risk; still human-supervised in many cases. 
Exfiltration & monetisation	Summarise stolen data, locate “high value” material, produce extortion notes, automate negotiation scripts, scale multi‑victim operations	High	Anthropic GTG-2002: AI triaged data, set ransom amounts, generated ransom notes and supported multi-target operations. 
 NCSC notes faster analysis of exfiltrated data increases impact. 
 FBI IC3 reports multiple scam categories with AI nexus. 
Monetisation still constrained by payment rails, LE disruption, and victim behaviour; negotiation is socio-technical. 

Technical evolution stages and milestone mechanics
A practical way to view the evolution is by “how tightly AI is coupled” to attacker execution:

Stage one: AI as a text/translation “copilot” (loose coupling)
Dominant in 2023–early 2025: LLMs improve phishing copy, translation, summarisation, and basic coding assistance, but do not directly execute attacks. This is consistent with Trend Micro’s 2023 underground observations (“hype vs reality”) and GTIG’s January 2025 conclusion that AI use was mainly productivity gains, with failed jailbreaks and limited novelty. 

Stage two: AI as an operational workflow amplifier (medium coupling)
By 2024–2025, credible reports show AI inserted into the workflow for identity fabrication, insider-style access (IT worker schemes), and improved vishing, supported by rising quantitative indicators (e.g., vishing growth and national loss reporting). 

Stage three: Embedded AI in tooling, including runtime LLM queries (tight coupling)
GTIG disclosed families where malware interacts with LLM APIs during execution (e.g., PROMPTSTEAL / PROMPTFLUX) and uses LLM output to generate executable commands or regenerate code. 
 Mandiant explicitly frames this as a shift toward adaptive malware and “LLM-as-external guidance/C2-like component.” 

Stage four: Agentic intrusion orchestration (tight coupling + autonomy)
Anthropic’s 2025 disclosures are the most detailed public descriptions of agentic tooling used as an “operator,” including multi-agent orchestration and high tactical autonomy (with human strategic gating and noted hallucination failures). 

Stage five: Abuse of legitimate AI services as infrastructure (service-as-attack surface)
The SesameOp case illustrates a distinct mechanism: threat actors abusing a legitimate AI API as a covert comms channel, reducing their need to host traditional C2. 

Mermaid ER-style sketch of an agentic intrusion architecture (conceptual)

strategic goals & approvals

summaries, evidence

Human operator

Orchestrator layer

Agent 1: Recon/OSINT

Agent 2: Vulnerability discovery

Agent 3: Credential discovery

Agent 4: Data triage/exfil planning

Target environment



Show code
This reflects publicly described patterns where AI agents handle discrete tasks and humans approve escalation gates. 

Quantitative statistics and trends
Phishing effectiveness and social engineering uplift
A peer‑review style arXiv paper validated on human subjects (101 participants) reported click-through rates of: 12% (control phishing emails), 54% (human experts), 54% (fully AI-automated), and 56% (AI with minimal human-in-the-loop). 
 This is one of the strongest controlled measurements available and supports the judgment that AI can match skilled human operators in persuasive email generation under experimental conditions.

Singapore’s national cyber landscape report found that ~13% of a small sample (40 unique phishing emails, ~1% of 2023 reported attempts) contained AI-generated content, while explicitly noting detection tools are imperfect and not 100% certain. 

Major vendor telemetry also suggests accelerating voice-based social engineering: CrowdStrike reported a 442% increase in vishing between H1 and H2 2024, linked to AI-driven phishing and impersonation tactics. 
 Mandiant’s M‑Trends 2026 executive edition reports that in 2025 investigations, voice phishing reached 11% of initial infection vectors (with email phishing declining to 6%), indicating a shift toward interactive attacks that bypass many automated controls. 

Deepfake fraud and synthetic identity trends
The Hong Kong deepfake video conference case quantified a single incident at HK$200 million transferred to five accounts, with the CERT describing the deepfake production flow and warning that public audio/video material was leveraged. 
 Microsoft’s Digital Defense Report 2025 describes large-scale fraud pressures, including $4B in fraud schemes blocked by Microsoft in one year (Apr 2024–Apr 2025), 1.6M fake account creation attempts blocked per hour, and that “AI-generated IDs” grew 195% globally in usage (as presented in the report). 

Government statistics on AI-linked cyber-enabled crime
The FBI’s 2025 IC3 annual report provides the clearest official quantification currently available:

22,364 complaints with AI-related information in 2025, with $893,346,472 in adjusted losses. 
“AI references by complaint loss” shows concentration in investment scams ($632M), followed by BEC ($30.3M) and multiple other categories (tech support, romance, personal data breach, employment, phishing/spoofing, etc.). 

The report explicitly warns this is likely an undercount because victims may not recognise AI involvement, especially in investment scams where overall losses exceed $8B. 
Underground ecosystem and marketplace patterns
Trend Micro’s 2023 “Hype vs Reality” report argues underground discussion focused heavily on jailbreaking and wrapping mainstream models rather than building genuinely novel criminal AI systems, and emphasises that criminals were using LLMs similarly to legitimate developers. 
 Trend Micro’s January 2026 update states the ecosystem has “industrialised,” with consolidation around jailbreak-as-a-service providers and deepfake commoditisation; it also argues that “on‑the‑fly code generation in malware” is operationally constrained by API key revocation and reliability, making it “unlikely to become mainstream” in the near term. 

GTIG independently observes a “maturing cyber crime marketplace for AI tooling” and multiple offerings supporting phishing, malware development, and vulnerability research. 

Charts and interpretation
The charts shown above visualise three evidence-backed patterns:

Investment fraud dominates recorded AI-linked losses in official US reporting (IC3), dwarfing other AI-cited categories. 
Controlled phishing outcomes show AI matches human expert performance (and far exceeds baseline phishing), supporting the view that AI most directly boosts social engineering effectiveness and scale. 
The “milestone count” line chart is a visibility proxy based on the number of major public disclosures included in this report, not a direct prevalence measure; it shows a disclosure inflection in 2025 consistent with multiple providers describing operationalisation. 
Reality vs hype
What AI truly changes, with strong evidence
AI is already changing cyber operations in ways that are observable and operationally useful:

Quality and speed of persuasion: LLMs lower language barriers, improve grammar/structure, and enable personalisation, which matters because many attacks remain human-targeted at the entry point. This is supported by controlled experiments and national-level observations (CSA). 
Scalability of impersonation: deepfake voice/video enables high-stakes impersonation (CEO/CFO, officials), meaning trust signals like “it looked/sounded like them” no longer suffice. 
Faster attacker iteration: malware authors can prototype, debug, port, and obfuscate faster; OpenAI’s “ScopeCreep” illustrates incremental malware engineering using LLM support. 
What is often marketing, speculation, or under-evidenced
“AI is writing novel zero-days at scale today”: major assessments and early vendor studies emphasise that AI mainly enhances existing TTPs and that advanced exploit development remains constrained by data quality and expertise, at least in the near term. 
“Fully autonomous hacking is common in the wild”: while some 2025 disclosures describe high-autonomy operations, official assessments still argue end-to-end advanced automation remains unlikely by 2027, implying autonomy is emerging but not ubiquitous. 
“Criminals are mostly using powerful sovereign criminal LLMs”: vendor research suggests most “criminal LLM” branding is wrappers/jailbreak services parasitising commercial models, with intermittent deception in underground marketing. 
Evidence for and against autonomous hacking in the wild
For: Anthropic’s Nov 2025 disclosure describes a campaign with AI conducting most tactical steps under human supervision, including multi-target orchestration and high throughput, with a published architecture diagram and explicit autonomy estimates. 
Against / limiting factors: the same disclosure notes hallucination and overstatement problems that force validation, and NCSC assessments maintain that fully automated end-to-end advanced attacks are unlikely to 2027. 
 Trend Micro also argues practical hurdles (revocable API keys, unpredictability) constrain some “AI malware” designs. 
Forecast and defender actions
Forecast scenarios
Next 12 months (to mid‑2027)

Most likely (≈60%): AI continues to amplify interactive social engineering (voice + messaging + video), with more routine deepfake use in payment fraud and impersonation; defenders see an uplift in “verification burden” and a shift from inbox-only training to multi-channel authentication. 
High-impact but less likely (≈25%): broader emergence of LLM-querying malware variants (runtime command generation) beyond isolated cases, enabled by stolen API keys and commodity toolkits sold in underground markets. 
Lower likelihood (≈15%): “agentic intrusion kits” become accessible to mid-tier criminals with turnkey orchestration, but reliability and detection pressures prevent widespread success at scale. 
Three-year horizon (to 2029)

Most likely (≈55%): AI enables faster vulnerability research and exploitation of known flaws, shrinking time-to-exploitation and increasing pressure on patching/attack surface management, consistent with NCSC’s medium-term assessment direction. 
Plausible (≈30%): AI-assisted “hands-off” intrusion segments become more common for well-resourced actors (state-linked and top-tier crime), with humans supervising but delegating execution; more abuse of legitimate AI/automation platforms as infrastructure (C2, data staging, automation). 
Less likely (≈15%): large-scale “autonomous exploit discovery” materially changes the zero-day landscape; this remains highly dependent on training data, compute, and expertise. 
Five-year horizon (to 2031)

Most likely (≈50%): AI-driven fraud becomes a mainstream operational risk across sectors; trust systems shift toward cryptographic and process-based verification rather than audiovisual cues; many organisations adopt “identity proofing hardening” and continuous verification. 
Plausible (≈35%): routine use of AI agents for parts of intrusion chains becomes standard among top-tier actors; defender “agentic SOC” approaches become necessary to maintain parity. 
Lower likelihood (≈15%): fully autonomous, end-to-end campaigns become common; even optimistic autonomy evidence today shows meaningful limits and human gates, and official assessment remains sceptical through 2027. 
Defender blindspots and early-warning indicators
Blindspots that AI exacerbates

Voice/video trust: executive requests, helpdesk processes, and vendor-payment workflows susceptible to deepfake impersonation. 
Identity and “legitimate access” abuse: increased use of stolen credentials, insider-style access paths, and malware-free intrusion patterns, which combine with AI-accelerated social engineering. 
Egress to AI APIs: malware/service abuse that blends into normal traffic when organisations permit AI tooling widely. 
Early-warning indicators

Sudden growth in stolen/abused AI API keys or unusual token usage patterns (especially from non-enterprise endpoints). 
Detection of malware patterns that query external model endpoints at runtime (LLM-as-brain). 
Sharp increase in voice-based social engineering incidents (helpdesk MFA resets, finance approvals), consistent with Mandiant/CrowdStrike trends. 
Increased deepfake presence in KYC/identity proofing attempts (synthetic IDs, liveness bypass attempts), consistent with Microsoft’s fraud reporting. 
Defender-focused action list
Harden high-risk business processes (finance, treasury, payroll, vendor onboarding) with mandatory out‑of‑band verification and dual-control approvals; treat voice/video as untrusted inputs for authorising transfers. This directly addresses demonstrated deepfake fraud playbooks. 
Expand security awareness beyond the inbox to include vishing, messaging apps, and video calls; train staff on “verification rituals” (call-back to known numbers, internal code words, identity escalation). This aligns with observed shifts toward interactive attacks. 
Instrument and monitor AI tool usage and egress: maintain an inventory of permitted AI services, enforce egress controls, and alert on abnormal API usage (volume, geography, user-agent anomalies). This becomes critical if AI APIs can be abused as C2. 
Strengthen identity security and continuous verification (phishing-resistant MFA, conditional access, helpdesk hardening, device posture checks). Many modern intrusions are malware-free and identity-driven; AI mainly improves the attacker’s “front door” success rate. 
Reduce blast radius of data theft: least privilege for data stores, aggressive secrets management, DLP for sensitive repositories, and rapid incident response playbooks for exfiltration detection—because AI enhances the attacker’s ability to triage stolen data for value. 
Prepare for adaptive malware and rapid iteration with behaviour-based detection, script-control policies, and EDR coverage beyond traditional endpoints (edge/virtualisation layers), consistent with M‑Trends guidance. 
Methodology and bibliography
Methodology
Source prioritisation: This report prioritised primary and quasi-primary sources: government advisories and annual reports (IC3/FBI, NCSC, CSA, HKCERT), AI provider threat intelligence (OpenAI, Anthropic, GTIG), and top-tier vendor reporting (Microsoft, CrowdStrike, Mandiant). Secondary media was used sparingly and mainly when it carried unique incident details later reflected in official advisories. 

Inclusion criteria for “AI-enabled” incidents: included events where AI was (a) used to generate/modify content for deception, (b) used to generate/modify code for malware/tools, (c) embedded in execution (runtime LLM querying or agentic orchestration), or (d) used to scale identity abuse.

Uncertainty handling: Several data points require explicit caution:

AI attribution is often underreported because victims cannot reliably detect AI involvement (explicitly noted in IC3 reporting and CSA’s detection caveats). 
Provider threat reports show only the slice of malicious activity visible to that provider/platform; absence of evidence is not evidence of absence. 
Bibliography with URLs and publication dates (selected primary sources)
text
Copy
2019-09-05  Sophos — “Scammers deepfake CEO’s voice to talk underling into $243,000 transfer”
https://www.sophos.com/en-us/blog/scammers-deepfake-ceos-voice-to-talk-underling-into-243000-transfer

2024-02-07  HKCERT — “Phishing Alert… fraudulent video conference scam using AI Deepfake technology”
https://www.hkcert.org/security-bulletin/phishing-alert-phishing-campaigns-targeting-instagram-backup-codes-to-bypass-2fa-on-the-rise_20240207

2024-02-14  Microsoft Security Blog — “Staying ahead of threat actors in the age of AI”
https://www.microsoft.com/en-us/security/blog/2024/02/14/staying-ahead-of-threat-actors-in-the-age-of-ai/

2024-01-24  UK NCSC — “The near-term impact of AI on the cyber threat”
https://www.ncsc.gov.uk/sites/default/files/pdfs/publication/impact-of-ai-on-cyber-threat.pdf

2024-05-08  FBI (field office) — “FBI Warns of Increasing Threat of Cyber Criminals Utilizing Artificial Intelligence”
https://www.fbi.gov/contact-us/field-offices/sanfrancisco/news/fbi-warns-of-increasing-threat-of-cyber-criminals-utilizing-artificial-intelligence

2024-07-30  Cyber Security Agency of Singapore — “Singapore Cyber Landscape 2023” (PDF)
https://isomer-user-content.by.gov.sg/39/38ef0201-7485-45f1-90c4-7246d8bcba1a/singapore-cyber-landscape-2023.pdf

2025-01 (report)  Google GTIG — “Adversarial Misuse of Generative AI” (PDF)
https://services.google.com/fh/files/misc/adversarial-misuse-generative-ai.pdf

2025-02-27  CrowdStrike — “2025 CrowdStrike Global Threat Report…” (press release)
https://www.crowdstrike.com/en-us/press-releases/crowdstrike-releases-2025-global-threat-report/

2025-05-07  UK NCSC — “Impact of AI on cyber threat from now to 2027”
https://www.ncsc.gov.uk/sites/default/files/pdfs/publication/impact-ai-cyber-threat-now-2027.pdf

2025-06-01  OpenAI — “Disrupting malicious uses of AI: June 2025” (PDF)
https://cdn.openai.com/threat-intelligence-reports/5f73af09-a3a3-4a55-992e-069237681620/disrupting-malicious-uses-of-ai-june-2025.pdf

2025-08 (report)  Anthropic — Threat Intelligence Report (August 2025) (PDF)
https://www-cdn.anthropic.com/b2a76c6f6992465c09a6f2fce282f6c0cea8c200.pdf

2025-11 (report)  Anthropic — “Disrupting the first reported AI-orchestrated cyber espionage campaign” (PDF)
https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf

2025-11-03  Microsoft Security Blog — “SesameOp: Novel backdoor uses OpenAI Assistants API for command and control”
https://www.microsoft.com/en-us/security/blog/2025/11/03/sesameop-novel-backdoor-uses-openai-assistants-api-for-command-and-control/

2025-11 (report)  Google GTIG — “Advances in Threat Actor Usage of AI Tools” (PDF)
https://services.google.com/fh/files/misc/advances-in-threat-actor-usage-of-ai-tools-en.pdf

2025-12-19  FBI IC3 — “Senior U.S. Officials Continue to be Impersonated…” (PSA)
https://www.ic3.gov/PSA/2025/PSA251219

2026-01-28  Trend Micro — “An Update on the State of Criminal AI: Crime as a Service, AI as the Multiplier”
https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/the-state-of-criminal-ai

2026-03-09  Google Cloud / Mandiant — “AI risk and resilience: A Mandiant special report”
https://cloud.google.com/security/resources/ai-risk-and-resilience

2026-03-30  Mandiant — “M-Trends 2026 Executive Edition” (PDF)
https://services.google.com/fh/files/misc/m-trends-2026-executive-edition-en.pdf

2026 (annual report)  FBI IC3 — “2025 IC3 Annual Report” (PDF)
https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf

Academic (arXiv HTML)
2024-12 (versioned)  Heiding, Lermen, Kao, Schneier, Vishwanath — “Evaluating LLMs’ capability to launch fully automated spear phishing… (human subjects)”
https://arxiv.org/html/2412.00586v1
