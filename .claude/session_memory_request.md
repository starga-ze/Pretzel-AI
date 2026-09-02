# Session record request

This file is an instruction to paste, not a summary. It is the rule.

---

## Task

Record this session's work on this repository as a single `.md` file under
`.claude/session_memory/`.

## Filename

```
YYYY-MM-DD-english-title.md
```

- Title in **English**, kebab-case, 2-4 words. e.g. `turn-path-restructure`, `chat-history-recovery`
- If a file for the same day already exists and the subject continues, append to it. A different
  subject gets a new file
- Date is the day the work was done

## Language

**The filename is English. Everything inside the file is Korean.**

This document is in English because it is a rule that stays put; what it produces is read back by
a Korean speaker looking for what was decided last time, and that reads faster in Korean.

## Content rules

- Write in **Korean**
- **End on nouns**
- No narrative endings.
- Use tables and code blocks. Do not lay things out as prose paragraphs
- Name file paths and symbols. Never "the function that does X"

## Sections

Follow this order. Omit a section that does not apply. The headings stay Korean.

```
# YYYY-MM-DD — 한글 제목

## 최종 구조          Directory tree. Only for a session that changed the structure
## 수행                What was done, grouped by subject
## 처리한 결함          A table: location / what it was
## 검증                What was actually run. Separate what was verified from what was assumed
## TODO              Where the next session starts
```

## Must include

- **The reason for a decision.** Why outlives what. When a **previous decision was reversed**,
  record the original reason alongside the new one — without it, someone reverts it back
- **Measured facts.** What was learned by probing the running system rather than by reading docs.
  Date them
- **Defects down to the cause.** A symptom alone means finding the same thing again next time
- **How it was verified.** Not "confirmed working" but what was run and what it produced

## Must not include

- The conversation, or a narration of how the work proceeded
- Anything the repository already states (file listings, function signatures)
- Text a person typed, API keys, credentials
- Impressions, assessments, praise

## Unresolved items

Write them so the next session can pick them up. Each one carries **why it was not done** and
**which file to touch**. An item that only says "later" is worth nothing.
