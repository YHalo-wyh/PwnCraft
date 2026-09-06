# Logs / Diagnostics Architecture

The fourth workspace tab uses `StructuredLogEvent` and `StructuredLogModel`, not a plain text-only timeline.

Fields: timestamp, category, severity, source, operation ID, message and structured details. Categories are Analyzer, Replay, Correction, Validation, Calibration, Debugger and System. The UI filters by category, severity and free text and reports category totals.

Heap presents only the currently selected checkpoint. Timeline history, operation detail, before/after and calibration detail belong in Logs or the Pwndbg operation history. The Heap page exposes only Current Operation, Field Edit and Function Adapter pages; AI correction and legacy timeline pages are not mounted.

Pwndbg command history remains distinct: it stores user-entered terminal commands and frame/runtime events, while Logs records application analysis and correction events.
