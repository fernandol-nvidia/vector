`vector validate --no-environment` now correctly rejects sink configurations with unconfined templates (e.g., `{{ tenant }}`) that would fail at runtime. Previously, such configurations would silently pass validation and only fail when Vector attempted to start.

authors: thomasqueirozb
