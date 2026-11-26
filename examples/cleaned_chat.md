The retry loop change looks correct. `client.py` now retries with jitter and the new tests cover the timeout path.

build status

One thing to double-check: the `Retry-After` header is parsed as an integer, so a date value would raise. See the HTTP semantics RFC.





coverage report





Thank you for the review!
