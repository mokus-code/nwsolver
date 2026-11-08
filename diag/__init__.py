"""Diagnostic suites — one per question the user asks.

* ``connection`` — "I have no internet": finds the broken link in the chain
  adapter → link → IP → route → router → internet → DNS → web.
* ``speed`` — "the internet is slow": measures each segment and names the
  bottleneck.
* ``resource`` — "this site doesn't open": follows one target through
  DNS, TCP, TLS and HTTP and says who is at fault.

Each module defines ``SUITE_ID``, ``SUITE_NAME``, ``SUITE_DESC``,
``PARALLEL``, ``make_checks(ctx) -> list[Check]`` and
``analyze(results, ctx) -> Verdict``.
"""
from nwsolver.diag import connection, resource, speed

SUITES = [connection, speed, resource]
SUITE_BY_ID = {s.SUITE_ID: s for s in SUITES}
