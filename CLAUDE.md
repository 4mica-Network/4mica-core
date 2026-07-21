# 4mica-core

## Comments

Write comments only where code cannot speak for itself.

- **Do** document public APIs (`pub` items): what it does, and any contract a caller
  must honor.
- **Do** explain non-obvious logic: an invariant, a subtle ordering requirement, a
  workaround, or *why* an approach was chosen when the obvious alternative is wrong.
- **Don't** restate what the code already says. No `// increment counter`, no comments
  that paraphrase the function name, no section banners.
- **Don't** narrate history or review context ("changed to fix X", "this is now
  correct", "as requested", "used to be a Y"). Comments are for the next reader of the
  code, not for the reviewer of the diff. If a comment only makes sense to someone who
  saw the previous version, delete it.

Style:

- **Be brief.** A long comment is worse than a short one — it buries the point and
  rots faster. One sharp sentence beats a paragraph.
- **Sound natural.** Write like a colleague explaining, not like a spec. No throat
  clearing, no restating the same idea twice in different words.
- **Be self-contained.** A comment should make sense to someone reading only this file.
- **Don't reach outside the reader's context.** Don't cite tickets, other systems, or
  concepts the reader has no access to and no need for — e.g. don't explain a generic,
  standalone crate in terms of the domain that happens to consume it. Refer to another
  module only when a reader genuinely must go look.

When in doubt, leave it out — a wrong or redundant comment costs more than a missing one.

## Commits

Do not add a `Co-Authored-By: Claude` trailer (or any AI attribution) to commit messages.
