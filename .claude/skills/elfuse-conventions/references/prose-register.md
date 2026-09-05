# The machine register

Every class here binds every prose surface elfuse carries: source comments,
commit messages, PR bodies and review replies, `docs/`, and the skill files
themselves. The sections in `SKILL.md` name only their own instance of one.

The two rules that come first, ASCII with no markdown syntax and the em dash
ban, stay in `SKILL.md` because they are checkable with a grep and get checked
constantly. What follows is the judgment half.

State the fact and stop:

- Describe the thing, not the change: no "previously", "now we", "we
  refined", or "fixed", and no history of prior attempts or review rounds.
  A decision that still matters is present-tense rationale.
- Inflation words ("delve", "seamless", "robust", "leverage") and empty
  pivots ("it's worth noting"): a sentence that survives deleting the phrase
  never needed it.
- Coined vocabulary, figurative accounting, and anthropomorphism: every
  noun for a mechanism is an identifier in the tree or the standard term
  from a man page, ELF or FUSE clause, or kernel source, and a value is
  computed, cached, discarded, or re-derived. Name the flag or function
  carrying the fact; a coined word cannot be grepped later.
- Trailing "-ing" glosses (", ensuring ..."): the tail names a checkable
  mechanism or goes.
- Negative parallelism ("not X, but Y"): say Y. Copula avoidance ("serves
  as", "acts as"): write "is".
- Rule-of-three padding, stacked transitions ("Moreover"), wrap-ups ("In
  conclusion"), hedge stacking ("could potentially"): cut; one hedge at
  most, for real uncertainty.
- Signposting, prompt echo, and the closing verdict: no announcement of what
  the text is about to do ("This commit will", "Below we describe"), no
  first line restating the subject or the PR title, and no closing sentence
  grading the change ("this makes the code more maintainable"). The last
  sentence carries a fact.
- Effort and flattery: "carefully reviewed", "comprehensive", "thoroughly
  tested", "Great catch", "You're absolutely right". Effort is not a
  finding; name what ran and what it reported.
- Deferral and self-report: an offer to redo the work another way ("say so
  and I will", "happy to split this"), an apology for a correction, or an
  announcement of candor before a caveat that stands on its own ("worth
  flagging rather than hiding"). State the decision and the reason that
  settles it; a reviewer who disagrees says so without being invited.
- Formatting as emphasis in docs and PR text: bolded bullet-header runs
  where a paragraph belongs, decorative rules, emoji.
- Machine artifacts, defects on sight: zero-width and bidi characters,
  homoglyphs, non-standard spaces, unfilled placeholders, leaked citation
  markup. Legitimate Unicode lives in `docs/` (the casefold tables), so scan
  the invisible class only, with a planted positive:

  ```
  grep -rnPI '[\x{00A0}\x{200B}-\x{200F}\x{202A}-\x{202F}\x{2060}\x{FEFF}]' src/ tests/ docs/
  ```
