# NNNN: Title

- **Status:** proposal | accepted | shipped | rejected | superseded
- **Issue:** rad:<issue-id>
- **Affects:** <spec docs / schemas / wire routes / canonical bytes? yes-no>

## Problem

What gap or need this addresses, and why now.

## Design

The change, precisely. If it touches canonical bytes: state the compatibility
rule (additive field? omit-when-empty? new versioned scheme?) and the vector
plan. If wire-visible: the route/shape and the conformance check it gains.

## Compatibility

What an implementation that ignores this remains conformant at. What the
byte-compat regression gate is.

## Shipped as (fill on landing)

- Spec: <sections>
- Vectors: <files>
- Guards: <protocol_checks names / conformance checks>
- Implementations: <python + ts commits>
