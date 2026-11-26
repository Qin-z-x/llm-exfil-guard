# Review response

The retry loop change looks correct. `client.py` now retries with jitter and the
new tests cover the timeout path.

One thing to double-check: the `Retry-After` header is parsed as an integer, so
a date value would raise.

Thank you for the review!
