# Homework 6 screencast guide

FAU ID: rallaf2022

Record your own narration. Keep the video under five minutes and turn the
camera on initially. The app and tests were generated in Cursor Agent from
the two prompts in prompts.txt. Git setup and verification were performed
separately; do not claim Cursor executed commands it did not execute.

## Suggested sequence

1. **0:00–0:20 — Camera and introduction.** State your name, FAU ID, coding
   agent (Cursor), and app purpose: offline analysis of login events.
2. **0:20–0:45 — Clone.** In a new disposable recording directory, run
   `git clone https://github.com/rallaf2022/gensec-Allaf-rallaf2022.git`.
   Open the clone in Cursor. Show `homeworks/Homework6/hw6/prompts.txt`.
3. **0:45–1:00 — Prompt overview.** Explain that Prompt 1 defines the app
   and initial security requirements, and Prompt 2 fixes a real constant-name
   bug and adds adversarial-input regression tests.
4. **1:00–2:40 — Replay from scratch.** In the disposable clone only,
   preserve prompts.txt, this guide, and screencast_url.txt. Move the
   generated app.py, sample_events.jsonl, README.md and tests directory into
   a backup directory outside the workspace. Paste Prompt 1 in a fresh
   Cursor Agent chat, then Prompt 2 after generation completes. These are
   the actual prompts; do not silently substitute hand-written code.
   If generation takes too long, edit or speed up waiting time and clearly
   label that portion. Keep your explanations and demonstration narrated.
5. **2:40–3:30 — Demonstrate.** From the regenerated hw6 directory:

   ```powershell
   py app.py --demo
   py app.py --file sample_events.jsonl --json
   py app.py --file sample_events.jsonl --threshold 4
   py -m unittest discover -s tests -v
   ```

   Expected saved-version sample result: 11 records, 8 valid, 3 rejected;
   203.0.113.10 is flagged at threshold 3 and not at threshold 4. Generated
   replay code can differ, so report its actual results.
6. **3:30–4:25 — Security and limitations.** Discuss strict types and
   fields, IP parsing, timezone-aware timestamps, bounded input, duplicate
   JSON-key rejection, control-character rejection, nested-JSON and
   timestamp-overflow handling. No network requests, shell execution, or
   external packages are needed. Explain per-IP false positives behind
   NAT, missed distributed attacks, capped/incomplete reports, invalid
   UTF-8 file refusal, and that path checks are not an OS sandbox.
7. **4:25–4:50 — Wrap up.** Show the repository, prompts and results.

## After recording

- Upload to your YouTube account as **Unlisted**.
- Open the video URL in an incognito window and verify playback without
  signing in. Do not assume visibility from the signed-in owner view.
- Put the real URL in screencast_url.txt and the Google homework document.
- Commit and push screencast_url.txt.
- Export the updated homework document as PDF and upload it to the correct
  Canvas homework assignment. The current report is a draft until the
  recording and its URL are added. No video or Canvas submission has been
  completed in this session.
