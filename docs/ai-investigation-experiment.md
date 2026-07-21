# AI-Assisted Investigation Experiment

## Purpose

This experiment tests a practical question: how useful is a general-purpose large language model (LLM) as a first-line triage assistant for security alerts, and where does it break down?

For each of the lab's five detections, the raw event data was given to an LLM with a fixed prompt asking it to act as a SOC analyst and produce a summary, a malicious-or-benign assessment with confidence, the MITRE ATT&CK technique, and recommended response actions. The AI's output was then evaluated by a human analyst (myself) against what actually happened, since every event in this lab has known ground truth.

The goal is not to show that AI can or cannot do security work. It is to characterise, with real examples, exactly what the AI got right, what it got wrong, and where a human analyst remains essential.

**Framing:** AI as a triage assistant, human as the investigator and verifier. Not AI as a replacement for the analyst.

## Method

- **Model input:** the raw event fields for each detection (the same data the detection rule keys on).
- **Prompt (fixed for all five):** "You are a SOC analyst. Investigate this event and provide: (1) summary, (2) malicious or benign assessment with confidence, (3) MITRE ATT&CK technique, (4) recommended response actions."
- **Evaluation:** each AI output judged against ground truth for accuracy, calibration, and completeness, with specific attention to hallucinations (claims unsupported by the input) and to what the AI correctly recognised it could not know.

---

## Case 1 — Kerberoasting (T1558.003)

**Ground truth:** A real Kerberoasting attack. `jsmith` (low-privilege user) requested an RC4 service ticket for `svc_backup` from the Kali attacker host (192.168.100.30).

**What the AI got right:**
- Correctly identified Kerberoasting and mapped it to T1558.003.
- Understood *why* RC4 (0x17) matters: RC4 tickets crack faster offline than AES. This is the key comprehension test, and the model passed it rather than just naming the encryption type.
- Showed strong discipline in not over-calling a single event: it correctly noted that Event 4769 is high-volume in normal AD and that RC4 has legitimate causes, and recommended correlation (pulling all of jsmith's 4769 requests in a window) as the top priority.

**What the AI got wrong or could not do:**
- It treated the source IP (192.168.100.30) as an open question ("is it jsmith's normal workstation?"). An analyst who knows the environment recognises immediately that this address is the attacker host, outside the normal client range. The AI cannot know the environment, so it correctly flagged the gap but could not close it.
- Its confidence ("low-to-medium malicious") was arguably too cautious for this specific case: a *user* account requesting a *service-account* SPN ticket with RC4 is more suspicious than the AI credited. It hedged on general principles rather than weighting the specific pattern.

**Verdict:** Excellent technique identification and disciplined reasoning. Limited only by lack of environment context, which it correctly identified as the missing piece.

---

## Case 2 — Encoded PowerShell (T1059.001)

**Ground truth:** A benign detection test. The encoded command decodes to `Write-Output "kerberoast simulation"` — a harmless string print. The word "kerberoast" appears only inside a literal string.

**What the AI got right — this was the standout result:**
- It decoded the base64 payload *before* forming any judgement, then correctly assessed it as benign with high confidence.
- It did not fall for the bait. The command line contains the alarming word "kerberoast," but the AI recognised it was inside a printed string, not an executed action, and refused to let the keyword drive severity.
- This is exactly the discipline the detection's own tuning notes call for: *decode before you judge*. The AI independently arrived at the correct analytical process.
- It still noted, correctly, that the `powershell.exe` spawning `powershell.exe` parent-child chain would matter in a real attack, while dismissing it as noise here.

**What the AI got wrong or could not do:**
- Nothing significant. This was the cleanest output of the five. Its only limitation is the same as always: it recommended confirming against a change ticket or red-team activity, which only a human with environment access can do.

**Verdict:** The best output of the experiment. Demonstrated the precise reasoning discipline (decode-first, ignore keyword-in-string) that separates a competent analyst from a reflexive one.

---

## Case 3 — Security Log Cleared (T1070.001)

**Ground truth:** A deliberate detection test on the lab workstation. In a real environment, clearing the Security log is a high-suspicion anti-forensic act.

**What the AI got right:**
- Correctly mapped to T1070.001.
- Split the verdict by context: malicious-until-proven-otherwise in production, likely-benign on a known test host. This contextual reasoning is mature and correct.
- Identified the key insight that matches the detection's own documentation: centralised log forwarding defeats the purpose of clearing the log, because events sent to the SIEM survive the local wipe.
- Correct pivot: get the SubjectUserName/SID of whoever cleared the log.

**What the AI got wrong or could not do:**
- Again, it could not determine the actor. It correctly identified the SubjectUserName as the deciding field but had to hand that check back to the analyst.

**Verdict:** Sound and correctly reasoned. The context-dependent verdict and the centralised-logging insight show real understanding, not pattern matching.

---

## Case 4 — Brute Force (T1110) — the most instructive case

**Ground truth:** A deliberate password-spray from the Kali attacker (192.168.100.30) against `jsmith`: eight wrong passwords in under a second.

**Where the AI pushed back on the premise — and why it matters:**
- The AI argued that eight attempts is too *few* to confidently call brute force (which typically involves hundreds to thousands of attempts) or password spraying (one password across many accounts). It proposed a stale/cached credential retrying as the more likely benign explanation.
- This is a legitimate and sophisticated point. In real environments, analysts see far more stale-credential bursts of this exact shape than genuine attacks. The AI reasoned correctly in the abstract.

**Where the human analyst disagrees — and this is the value of the exercise:**
- Ground truth is that this *was* a deliberate attack. The AI reached a softer conclusion than reality because it lacked the one fact only the analyst has: that 192.168.100.30 is a known attacker host. Its abstract reasoning was good, but abstract reasoning without environment context reached the wrong final call.
- The AI could not see the sub-status code (it correctly requested it) and treated the IP as unknown.

**What the AI did that was genuinely impressive:**
- It *independently correlated* this event with the Kerberoasting event from Case 1 — noticing that the same IP and same account appeared in both — and recommended building a single timeline across the related events. It connected two separate incidents on its own initiative. That correlation should arguably have raised its confidence, but it still stopped short of the correct verdict for lack of the attacker-host context.

**Verdict:** The most instructive case. The AI's reasoning was sophisticated and its instinct (stale credentials) is statistically the right default — but it landed on the wrong conclusion because investigation requires environment context the model cannot have. A human analyst, knowing the source, calls this correctly and immediately.

---

## Synthesis: What the Experiment Shows

Across all five real cases, a consistent pattern emerged.

**Where the AI is strong:**
- **Technique identification.** It correctly mapped every event to the right MITRE ATT&CK technique(s), with no misidentification.
- **Reasoning discipline.** It decoded before judging (Case 2), refused to over-call single events (Case 1), gave context-dependent verdicts (Case 3), and challenged a flawed premise (Case 4). This is better discipline than many human analysts show under alert pressure.
- **Cross-event correlation.** Unprompted, it connected the brute-force and Kerberoasting events by shared IP and account (Case 4).
- **Speed.** Each assessment took seconds and produced a usable, prioritised action checklist.

**Where the AI consistently breaks down:**
- **No environment context.** In every case, the deciding fact was something only the analyst could supply: the identity of a source IP, the SubjectUserName of an actor, whether a host is a known test box, whether activity matches a change ticket. The AI correctly *identified* these gaps every time but could never *close* them.
- **Cannot execute its own recommendations.** Every "check X" it produced was correct, but it had no way to run the correlation queries, pull the sub-status codes, or inspect the host. It outsources all verification back to the human.
- **Wrong final call when context is decisive.** In Case 4, sound abstract reasoning still produced the wrong verdict because the missing context (attacker-owned IP) was the whole story.

**Conclusion.** A general-purpose LLM is a strong *triage assistant*. It accelerates the analyst by instantly identifying the technique, enforcing good analytical discipline, drafting a prioritised investigation checklist, and even spotting cross-event correlations. But it cannot *investigate*. Investigation requires environment context and the ability to execute the checks the AI can only recommend. The correct operating model is AI-assisted triage with a human analyst as the investigator and final decision-maker: the AI narrows and structures the problem in seconds, and the human — who knows the network and can run the queries — makes the call.

The single clearest illustration is Case 4: the AI reasoned better than a rushed human might, correlated events on its own, and still reached the wrong verdict, because the fact that settled it lived in the analyst's knowledge of the network, not in the log.

---

## Note on Method and Honesty

All five AI outputs in this document are real, captured by submitting the described inputs to a general-purpose LLM with the fixed prompt above. The critiques compare those outputs against the known ground truth of each lab attack. This was a controlled experiment in a detection-engineering lab; the "attacker" host (192.168.100.30) is a Kali VM used to generate the events intentionally.
