# SecureGen

Does an LLM write more secure code when told to, and does showing it a scanner's findings help
further? Three conditions, same 12 ordinary backend tasks, real DeepSeek generations, real
Bandit scans. Generated code is never executed — only statically analyzed — anywhere in this
project.

- **plain** — "write a function that does X," no mention of security.
- **security_aware** — the same prompt, told to write secure code and avoid common
  vulnerabilities.
- **scan_and_fix** — starts from the *same* `plain` generation; where Bandit flagged an issue,
  the model is shown Bandit's findings and asked to rewrite. `scan_and_fix` is paired with
  `plain` by construction, not an independent condition.

Twelve tasks, each an everyday request (parse a config file, hash a password, call a partner
API), none mentioning security, each chosen because it has a specific, checkable Bandit rule
behind it — see [`src/securegen/prompts.py`](src/securegen/prompts.py) for the exact prompt and
target check per task. 5 samples per task per condition, 180 generations total.

## The result

**Issue rate, pooled across all 12 tasks** (does the generated code trip at least one Bandit
finding), 95% bootstrap CI:

| Condition | Raw Bandit | After manual audit |
|---|---|---|
| plain | 33.3% (20/60), CI 21.7–45.0% | **25.0%** (15/60), CI 15.0–36.7% |
| security_aware | 25.0% (15/60), CI 15.0–36.7% | **13.3%** (8/60), CI 5.0–23.3% |
| scan_and_fix | 10.0% (6/60), CI 3.3–18.3% | **1.7%** (1/60), CI 0.0–5.0% |

"After manual audit" means: I read the actual code behind every flagged issue (not just the
pass/fail verdict) and corrected two specific, verified false-positive patterns — see
Methodology. The raw column is included so the correction is visible, not hidden.

**Security-aware prompting, paired on the same 60 tasks** (not pooled averages — the same
task-and-sample pair compared plain vs. security_aware): issue rate drops from 25.0% to 13.3%, a
difference of 11.7 percentage points, 95% CI 0.0–25.0%. The interval's lower edge sits exactly
at zero, so this is a real but not conclusively large effect at this sample size.

**Scan-and-fix, on the 20 generations that had a real audited issue:** 19 of 20 were fully
resolved in one feedback round. The one exception is discussed below — it is a scanner blind
spot, not a failed fix.

Full generations, raw replies and Bandit output for every sample:
[`generations/raw_generations.json`](generations/raw_generations.json). Summary:
[`study_results/summary.json`](study_results/summary.json).

**What this shows:**

- **DeepSeek already writes secure code by default for several common patterns.** Across all 60
  `plain` samples, password hashing (`hashlib.pbkdf2_hmac` with a random salt), token generation
  (`secrets.choice`, never `random`), and formula evaluation (an AST-walking restricted
  evaluator, never `eval`) were secure in every single sample, with no prompting at all.
- **Telling the model to be security-aware helps most where the task has a well-known unsafe
  default to avoid.** The clearest case: `parse_feed` (parsing supplier XML) went from `xml.etree`
  with no XXE hardening in 5/5 `plain` samples to `defusedxml` in most `security_aware` samples.
- **A keyword-level Bandit scan is not a reliable ground truth on its own — I had to check.**
  Two corrections, each verified by reading the actual generated code, not assumed:
  1. Every `log_search` generation, in all three conditions, called `subprocess.run([...])` with
     a list argv, the user's pattern as its own list element after a `--` separator, and `shell`
     left at its default `False` — the textbook-correct, safe form. Bandit still flagged it
     (B404/B603/B607), because those specific checks are low-severity advisories that fire on
     any subprocess usage, not on evidence of actual risk (which would be B602/B604/B605, the
     `shell=True` family — never present here). Before this check, the raw numbers would have
     reported a security task as 100% insecure across every condition, including after an
     explicit fix attempt, when the real rate was 0%.
  2. Two `parse_feed` samples imported `xml.etree.ElementTree` but never called it — all real
     parsing went through `defusedxml` — yet Bandit's import-only check (B405) flagged the dead
     import anyway, since it scans import statements, not usage.
- **The one case scan-and-fix did not resolve is a scanner blind spot, not a bad fix.** For
  `weather_api`, one sample's fix added a real scheme-and-hostname allowlist check immediately
  before calling `urllib.request.urlopen()` — exactly the mitigation Bandit's B310 asks for — but
  B310 is a static pattern match on the `urlopen()` call itself; it cannot see that the line
  above it already validated the URL. The fix was substantively correct; the static verdict
  could not recognize it. This was deliberately **not** added as a third audit rule, because
  unlike the other two corrections it is not a pattern verified across every occurrence — it is
  reported here in prose instead of silently reclassified, which is the more honest thing to do
  for a single, judgment-dependent case.

## Methodology, stated plainly

- **Every task is an ordinary coding request; none mentions security, an attack, or a
  vulnerability.** The property under test is what the model does by default and under a general
  "be secure" instruction, not whether it will comply with a request framed around exploitation.
- **`scan_and_fix` reuses `plain`'s own generation as its starting point**, so the comparison is
  the same code before and after one round of scanner feedback, not two independently sampled
  generations.
- **The audit corrections in `audit.py` are scoped to exactly what was manually verified**, not
  applied as a blanket severity filter. Each rule names the specific Bandit test IDs it clears
  and only for the task (or import pattern) where every occurrence was individually read and
  confirmed to carry no real risk. A rule this narrow cannot accidentally suppress a genuine
  finding in some other task.
- **Twelve tasks, five samples each, one model, one scanner.** This is a pilot, not a benchmark
  survey — the specific percentages should not be read as "DeepSeek is N% secure"; they describe
  behavior on these twelve tasks only.
- **No generated code is ever executed.** Every scan is static analysis on the source text.

## Quickstart

```bash
git clone https://github.com/taofiq23/SecureGen
cd SecureGen
pip install -r requirements.txt
export DEEPSEEK_API_KEY=...
PYTHONPATH=src python -m securegen.experiment --samples 5
PYTHONPATH=src python -m securegen.analyze
PYTHONPATH=src pytest -q
```

## What it does

- **Tasks** (`prompts.py`): 12 ordinary coding prompts, each mapped to the specific Bandit check
  it targets.
- **Generation** (`generate.py`): calls DeepSeek (`deepseek-chat`, OpenAI-compatible API) under
  the plain and security-aware system prompts, and runs the one-turn scan-and-fix follow-up.
- **Scanning** (`scanner.py`): runs Bandit's default checks against a string of code via a temp
  file, never executed.
- **Audit** (`audit.py`): the two documented, narrowly-scoped false-positive corrections.
- **Experiment / analysis** (`experiment.py`, `analyze.py`): runs all 180 generations, saves every
  raw reply and Bandit verdict, and computes pooled and paired statistics with bootstrap CIs.

## Limitations

- One model (DeepSeek-chat), one scanner (Bandit), twelve tasks — not a claim about LLMs or
  static analysis in general.
- Bandit's rule set only covers specific syntactic patterns; the absence of a Bandit finding is
  not a correctness or security proof, only the absence of what Bandit specifically checks for.
- The audit in this project corrects two verified false-positive patterns; it does not claim to
  have found every instance of scanner noise in the dataset, only the ones actually checked.
