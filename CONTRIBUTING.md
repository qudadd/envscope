# Contributing

Keep measurements separate from interpretations. A new probe must document its
transport, address family, timeout, external services, expected response shape,
and what it cannot prove. Add a regression for the misleading success case that
motivated the change. Tests must use synthetic inputs or loopback services.

Run the checks in README.md. Browser changes require a desktop screenshot
review at desktop widths and an interaction smoke test. Avoid runtime dependencies unless they add
an indispensable measurement capability. Scrapling stays in external research.

Do not copy code from a new upstream until its exact revision and license have
been checked. Add attribution and any required notices. Architecture references
do not mean those projects are bundled dependencies or verified integrations.

Do not commit reports, private policies, captured source pages, credentials,
profiles, or real network addresses. A default check may stay unknown when the
required evidence does not exist. Do not replace it with a reassuring heuristic.
