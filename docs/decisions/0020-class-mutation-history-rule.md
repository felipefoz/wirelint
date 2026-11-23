# LabVIEW class mutation-history rule

- Status: Accepted
- Date: 2026-11-18

## Context

LabVIEW class XML stores mutation history as content inside the root property
named `NI.LVClass.Geneology` with `Type="Xml"`. The rule should flag history
content, while an absent or empty property passes and non-class files remain
unaffected.

## Decision

Add the `class-mutation-history` built-in rule with warning severity. For
`.lvclass` files, read whether a direct `Property` child of the `LVClass` root
whose name is `NI.LVClass.Geneology` and type is `Xml` contains non-whitespace
text or child elements. Nonempty values are findings; missing, empty, or
whitespace-only values pass. Projects, libraries, and VI-family files have no
applicable fact and are skipped. The check does not validate the semantics of
history contents.

## Alternatives

- **Search the entire XML document:** a nested property might belong to another
  object and should not satisfy the class owner's metadata check.
- **Validate the history records:** the check is limited to content being
  present; record semantics are outside this rule's scope.
- **Treat non-class files as missing the element:** mutation history is a
  class-only property and this would create unrelated findings.

## Consequences

The XML reader records whether the class-root property has content with the
other shared facts. The rule uses the existing common enablement and severity
options; malformed XML continues to be reported as an analysis error by the
format reader.

## References

- [Rule architecture](0006-rule-runner-and-source-only-check.md)
- [Quality and hygiene rule guide](../user-guide/quality-rules.md)
- [Mutation-history removal hook](https://gitlab.com/felipe_public/lv-dev-hooks/-/blob/main/src/lv-dev-hooks/remove-mutation-history.vi)
