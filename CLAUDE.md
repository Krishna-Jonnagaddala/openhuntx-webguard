# Writing style for this repository

Anything written in prose in this project (markdown docs, code comments, docstrings, commit messages, PR descriptions, chat responses) should read like a person wrote it, not a model. Apply this everywhere, not just in one file someone remembered to check.

## Cut these

Words: delve, leverage, utilize (say "use"), harness, unlock, elevate, robust, seamless, boasts, meticulous, crucial, pivotal, vital, testament to, underscore, showcase, comprehensive, powerful, cutting-edge, state-of-the-art.

Openers and hedges: "it's worth noting," "it's important to note," "that said," "ultimately," "in conclusion," "in summary," "when it comes to," "in the realm of," "in today's ever-evolving landscape."

Constructions: "not only... but also," "whether it's... or..."

## Punctuation

No em dash, ever. Use a comma, a colon, parentheses, or just split the sentence. This project used to lean on "--" as a stand-in for the same thing; stop doing that too, it's the same tell in different clothes. Write it as an actual sentence instead.

Straight quotes and apostrophes only (`'` and `"`), never the curly ones.

Don't force an Oxford comma into every single list out of habit.

No emoji as bullets or in headings.

## Structure

Vary section and paragraph length on purpose. Not everything needs to be three items, three sentences, three bullets. If three is genuinely the right number, fine, but don't reach for it by default.

Stop doing **bold lead-in: one tidy sentence** on every bullet in a list. It's a dead giveaway. Some bullets can be a fragment, some can run long, some can just not have a bold prefix at all.

Don't open a doc by restating what it's about, and don't close with a paragraph that summarizes what was just said. Start with the actual content. Stop when there's nothing left to say.

Not every three-line thought needs its own heading, and not every section needs a horizontal rule under it. Let some things just be a paragraph.

Prose belongs in prose. Don't turn a paragraph into a table just because it has more than one fact in it.

## Tone

Say when something is a bad idea. Don't hedge every sentence into mush. If a docstring is explaining why a piece of code is safe or unsafe, say that plainly, with the actual mechanism, not with a wrapper of "it is worth noting that this may potentially."

Don't over-explain what's obvious from the code itself. Use specifics (real numbers, real file names, the real reason something broke) instead of a generic gesture at "improved reliability" or "better security."

## The actual test

If a sentence could sit unchanged in a document about a completely different project, it's too generic. Rewrite it so it's clearly about this thing, this decision, this bug.

## What this does not license

None of the above is permission to soften or blur a factual or security claim for the sake of tone. A docstring that says a lookup is safe because of a specific atomic SQL predicate, or unsafe because a check happens twice on two different connections, has to keep saying exactly that. Fix the prose around the claim, never the claim.

Style rules never justify changing technical meaning, exact identifiers, security claims, code, commands, quoted evidence, test expectations or historical audit facts.

Historical audit/evidence documents should preserve factual wording and proof status. If style conflicts with evidence accuracy, accuracy wins.

Machine-significant or externally registered names may retain otherwise disallowed punctuation when changing them could break an integration, status check, API contract or external dependency.
