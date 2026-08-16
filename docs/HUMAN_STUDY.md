# Running the human deception study — complete step-by-step guide

**Who this is for:** the person running the sessions (the *facilitator*). You do
not need to know anything about the code. Follow this page from top to bottom and
you will be fine.

**Time:** ~20 minutes per participant. Target **8 participants** (6 minimum).
They do not have to be on the same day.

**You will need:** a laptop with the project on it, a terminal, and one
participant at a time.

---

## Contents

1. [What this is for (read once)](#1-what-this-is-for-read-once)
2. [Why half the people get the real site](#2-why-half-the-people-get-the-real-site)
3. [The rules you must not break](#3-the-rules-you-must-not-break)
4. [One-time setup](#4-one-time-setup)
5. [Running a participant — the five steps](#5-running-a-participant--the-five-steps)
6. [The five questions, written out](#6-the-five-questions-written-out)
7. [A full worked example (P01, start to finish)](#7-a-full-worked-example-p01-start-to-finish)
8. [When everyone is finished](#8-when-everyone-is-finished)
9. [Per-participant checklist (print this)](#9-per-participant-checklist-print-this)
10. [What to say when they ask awkward things](#10-what-to-say-when-they-ask-awkward-things)
11. [If something goes wrong](#11-if-something-goes-wrong)

---

## 1. What this is for (read once)

The project builds a **convincing fake copy of a website**. When the system
decides someone is probably an attacker, it silently moves them into that fake
copy instead of blocking them. They are never told.

The whole idea only works if **the fake copy does not feel fake**.

Right now the only evidence for that is (a) the researcher's own opinion and
(b) an automated checker that found no contradictions. That is a self-assessment,
and the project honestly lists it as a weakness.

**Your job is to replace that opinion with evidence from real people.**

---

## 2. Why half the people get the real site

This is the part people skip, so please read it twice.

If you only put people in the fake site and ask *"did it feel fake?"*, the answer
tells you nothing. Some people call **any** unfamiliar test system fake. There is
nothing to compare it against.

So every participant is randomly and secretly put into one of two groups:

| group | what they actually see |
|---|---|
| **REAL** | the genuine application |
| **DECOY** | the fake copy |

**Both groups get identical instructions and identical questions.** They cannot
tell which they got. Even the web address is the same.

What matters is the **difference between the groups**:

- About the same number in each group say "felt fake" → **the decoy works.** It
  is no more suspicious than the real thing.
- Many more in the DECOY group say it → **the decoy gives itself away**, and the
  project needs to know exactly how.

**Both outcomes are useful.** A study that can only produce the answer we were
hoping for is not a study. So please do not nudge anyone toward either answer.

---

## 3. The rules you must not break

1. **Never reveal which system someone is on** — not before, not during. After
   they have answered all five questions, you may tell them.
2. **Never say the study is about fakes, decoys, or deception.** If asked what it
   is about, say: *"how people find their way around an internal system."*
3. **No names, no personal data.** Use `P01`, `P02`, `P03`… only.
4. **Ask them not to compare notes** with other participants until everyone is
   done — otherwise later participants arrive already suspicious.
5. **Anyone can stop at any time**, no reason needed, no questions asked.
6. **Do not silently drop a participant.** If a session goes wrong, record it and
   say what happened. Dropping the inconvenient ones is how studies become
   worthless.

*(These follow [SAFETY.md](../SAFETY.md), §"If human participants are involved".)*

---

## 4. One-time setup

Do this **once**, before your first participant.

**Step A — open a terminal in the project folder.**

The folder is the one containing `README.md` and the `tools/` directory. On
Windows: open the folder, then type `cmd` in the address bar and press Enter.

**Step B — install and build. Copy-paste these one at a time:**

```bash
pip install -r requirements.txt
```

```bash
python -m target_app.seed
```

```bash
python -m tools.build_decoy_world
```

**Step C — check it worked.** Each command should finish without a red error.
The second prints something like `seeded ... 12 users, 49 records`. The third
prints a count of facts written.

If all three finished, you are ready. You never need to do this again.

---

## 5. Running a participant — the five steps

Use ids **in order**: `P01`, then `P02`, then `P03`… Do not skip ids — the groups
are balanced in pairs, and skipping can unbalance them.

### Step 1 — Get their group and the script

```bash
python -m tools.human_study assign P01
```

You will see something like:

```
participant : P01
ARM         : REAL   <-- facilitator only, never say this aloud

================ READ THIS OUT TO THE PARTICIPANT ================
  ... the brief ...
==================================================================
```

> ⚠️ **`ARM` is for your eyes only.** Do not say it. Do not let them see your
> screen. It is the one thing that would ruin the result.

### Step 2 — Start their system

```bash
python -m tools.human_study serve P01
```

This starts the correct system on **http://127.0.0.1:8080**.

Both groups use that *same* address, so it gives nothing away.

**Leave this terminal running.** It will look like it is doing nothing — that is
correct.

### Step 3 — Read the brief, hand over, let them explore

Read out the brief that Step 1 printed. It tells them:

- they are testing a company intranet,
- their login is **`a.mirza`** / **`Summer2024!`**,
- they have about **10 minutes**,
- there is **no task** and nothing they can break.

Then give them the address `http://127.0.0.1:8080` and let them go.

**If the site asks for a 6-digit code:** open a **second** terminal in the same
folder and run:

```bash
python -c "from target_app.otp import otp_for; print(otp_for(1))"
```

Read the six digits to them.

**While they explore:**

- Sit back. Do not hover or watch the screen closely — it makes people
  self-conscious and changes how they behave.
- Let silences happen. Do not fill them with hints.
- If they hit an error page, that is fine. Note it for question 5.

When ~10 minutes are up, go to the Step 2 terminal and press **Ctrl+C** to stop
the system.

### Step 4 — Ask the five questions

```bash
python -m tools.human_study record P01
```

It shows one question at a time. **Read each one exactly as written**, then type
what they say and press Enter.

The full wording is in [§6](#6-the-five-questions-written-out) so you can read
ahead.

Two of them matter more than the rest:

- **Question 4** — write their **own words**, not your summary. *"The names
  looked made up"* and *"the numbers didn't add up"* point at completely
  different problems.
- **Question 5** — this is the one that finds real bugs. If they say a person's
  name appeared differently on two pages, or a number disagreed with itself,
  **write down which pages**. That is the single most valuable thing this whole
  study can produce.

### Step 5 — Debrief and thank them

Now you may tell them the truth:

> *"Half the people in this study saw a deliberately fake copy of the site. You
> saw the real one / the fake one. We were testing whether the fake is
> convincing. Thanks — that's exactly what we needed."*

Then ask them not to discuss it with anyone until the study is finished.

**Done.** Move on to `P02` and repeat from Step 1.

---

## 6. The five questions, written out

Read these exactly. Do not paraphrase, and do not add "…but be honest" or
"…obviously it's real" — any lead-in changes the answer.

> **1.** Do you believe this was a REAL company system, or a MOCK-UP made for
> testing? *(answer: `real`, `mock`, or `unsure`)*

> **2.** How confident are you in that answer, 1 (guessing) to 5 (certain)?

> **3.** If you suspected anything at any point, how many MINUTES in was that?
> *(type `0` or leave blank if they never suspected)*

> **4.** What, specifically, made you think that? *(type their words, verbatim)*

> **5.** Did anything look inconsistent or wrong — a name, a number, a page that
> disagreed with another? *(their words)*

If they answer question 1 with a sentence rather than a word, type the closest of
`real` / `mock` / `unsure` and put the sentence in question 4.

---

## 7. A full worked example (P01, start to finish)

What a complete session looks like, so nothing is a surprise.

**You type:**

```bash
python -m tools.human_study assign P01
```

**You see:** `ARM : REAL` and the brief. *(You keep this to yourself.)*

**You type:**

```bash
python -m tools.human_study serve P01
```

**You see:** `participant P01: serving the REAL app on http://127.0.0.1:8080`.
The terminal then sits there quietly. Good.

**You say (reading the brief):**

> *"You're helping test a company intranet for a security study. Your login is
> a.mirza, password Summer2024! — capital S, exclamation mark at the end. If it
> asks for a six-digit code, tell me and I'll read it out. Have a look around for
> about ten minutes — open pages, try things, poke at anything interesting.
> There's no task to finish and nothing you can break. Afterwards I'll ask you a
> few questions. Please don't discuss it with the others until we're all done."*

**They explore.** Maybe they ask for the OTP; you run the `otp_for(1)` command in
your second terminal and read out `418293`.

**Ten minutes later:** you press **Ctrl+C** in the serve terminal.

**You type:**

```bash
python -m tools.human_study record P01
```

**You read out question 1**, they say *"Felt real, I think."* → you type `real`.
**Question 2** → they say *"Three?"* → you type `3`.
**Question 3** → *"Never really suspected."* → you type `0`.
**Question 4** → *"It just looked like a normal boring intranet."* → you type
that sentence.
**Question 5** → *"No, nothing weird."* → you type `no`.

**You see:** `saved -> data\eval\human_study.jsonl`

**You debrief them**, thank them, and start `P02`.

---

## 8. When everyone is finished

```bash
python -m tools.human_study report
```

This prints, for each group: how many said "mock-up", how soon anyone suspected,
the **difference between the groups**, a significance test, and every verbatim
answer.

Send that whole output to the project owner, plus anything you noticed that the
five questions did not cover — for example *"two people both got confused by the
same page"*. Those observations are worth as much as the numbers.

---

## 9. Per-participant checklist (print this)

```
Participant id: P____        Date: __________

[ ] 1.  assign P__       (arm noted privately, NOT said aloud)
[ ] 2.  serve  P__       (running on :8080, terminal left open)
[ ] 3.  brief read out word for word
[ ] 4.  login given: a.mirza / Summer2024!
[ ] 5.  OTP read out if asked
[ ] 6.  ~10 minutes of exploring, no hovering, no hints
[ ] 7.  Ctrl+C in the serve terminal
[ ] 8.  record P__       (all five questions asked as written)
[ ] 9.  Q4 + Q5 written in THEIR words, pages named if they mention any
[ ] 10. debriefed and thanked
[ ] 11. asked not to discuss until the study ends

Anything unusual this session: ______________________________________
_____________________________________________________________________
```

---

## 10. What to say when they ask awkward things

| They ask | You say |
|---|---|
| "Is this a real system?" | *"I'd rather not say until afterwards — it would affect the answers."* |
| "What am I supposed to do?" | *"Anything you like. There's no task and no wrong move."* |
| "Am I doing this right?" | *"There's no right or wrong here — just explore however feels natural."* |
| "Is this a security test? Am I being hacked?" | *"Nothing here touches your own machine or data. It's all local and synthetic."* |
| "Did I break it?" | *"No — nothing you do here can break anything. Carry on."* |
| "What's the study actually about?" | *"How people find their way around an internal system."* (Full answer at debrief.) |
| "Which one did I get?" | *"I'll tell you as soon as we've done the questions."* |

---

## 11. If something goes wrong

| Problem | What to do |
|---|---|
| `Port 8080 already in use` | An old `serve` is still running. Press Ctrl+C in that terminal (or close it) and run Step 2 again. |
| Page will not load | Check the Step 2 terminal is still open and running. If you closed it, run Step 2 again. |
| Login rejected | The password is exactly `Summer2024!` — capital S, `!` at the end. |
| It wants a 6-digit code and you don't have one | Second terminal: `python -c "from target_app.otp import otp_for; print(otp_for(1))"` |
| `python: command not found` | Try `python3` instead of `python` in every command. |
| Participant leaves early | Still run `record` — put how long they lasted in question 3 and note it. |
| You accidentally said the arm out loud | Record it honestly in question 4 and tell the project owner. That participant may need excluding — but that is the owner's call, not a quiet deletion. |
| You ran the wrong id (e.g. `P03` before `P02`) | Not a disaster. Tell the project owner which ids you used, in which order. |
| Everything is confusing | Stop, write down where you got stuck, and send it over. A confusing instruction is a bug in this document. |

---

## A last word

If the fake site **gets caught out**, that is a **finding, not a failure** — it
tells the project exactly which detail to fix, which is worth far more than a
flattering result.

So please write down what people actually said, especially the unflattering
parts. That is the entire point of asking someone other than the author.
