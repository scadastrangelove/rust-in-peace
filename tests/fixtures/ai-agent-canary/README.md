# Evaluator-only corpus

These scenarios and fix/decoy labels are not copied into the finder image.
The synthetic target's Dockerfile copies only its application source. Discovery
evaluation must use an isolated source snapshot without this repository's
history, tests or expected results. Replay of this corpus is a regression test,
not a measurement of fresh vulnerability discovery.
