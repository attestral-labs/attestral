# Delta demo: the head revision that opens a path

Paired with `examples/delta-base`. The base design has a `fetcher` (an outbound
channel that also ingests untrusted web content) and a `db-reader` (reads a
production database with a stored credential). There is no code-execution
surface, so no injection can pivot: untrusted input has nowhere to go.

This head revision adds one server, `runner`, that launches a shell. That single
change supplies the missing pivot, so a reachable path now runs from untrusted
input through code execution to an outbound channel, and the lethal-trifecta
findings light up.

`attestral diff examples/delta-base examples/delta-head` renders exactly that as
a PR comment: the new server and the capability it gained, the newly reachable
attack path, the new findings ranked by severity, and the jump in worst-case
blast radius. It is the review a human reviewer would write, produced from the
system-model diff.
