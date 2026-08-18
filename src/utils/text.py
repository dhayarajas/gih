"""Guards that keep a tool's bytes from being read as text.

An OSINT tool prints back whatever the target served it: a fingerprinter handed
a TLS record or a compressed body writes those bytes to its pipe. Nothing in
such a capture is a finding, and a control character lifted out of it into an
artifact value follows that value into the database, into the HTML report and
into the log file, corrupting every reader downstream.
"""

import logging

# Whitespace a tool legitimately prints, and a reader can see. Vertical tab and
# form feed are not among them: they render as nothing, so they read as bytes
# that escaped a binary stream rather than as something a tool meant to say.
ALLOWED_WHITESPACE = frozenset("\t\n\r")

CONTROL_CHARACTERS = frozenset(
    chr(code) for code in (*range(0x20), *range(0x7F, 0xA0))
) - ALLOWED_WHITESPACE

# What a lenient decode leaves behind where a byte was not valid UTF-8.
REPLACEMENT_CHARACTER = "\ufffd"

# How much of a capture may be undecodable or control bytes before it is not
# text at all. A page title in an unexpected encoding costs a few characters;
# a binary stream is mostly unreadable.
MAX_UNREADABLE_SHARE = 0.10


def has_control_characters(text: str) -> bool:
    """Whether a string carries a control character that is not whitespace."""
    return any(char in CONTROL_CHARACTERS for char in text)


def is_textual(output: str) -> bool:
    """Whether a captured tool output can be read as text at all.

    Deliberately tolerant: a mostly readable capture with a few mojibake bytes
    in a title is still the run's evidence and is still worth parsing. Only a
    capture that is predominantly unreadable is rejected.
    """
    if not output:
        return True
    unreadable = sum(
        1 for char in output
        if char in CONTROL_CHARACTERS or char == REPLACEMENT_CHARACTER
    )
    return unreadable <= MAX_UNREADABLE_SHARE * len(output)


def escape_control_characters(text: str) -> str:
    """The same text with every non-whitespace control character escaped."""
    if not text:
        return text
    return "".join(
        f"\\x{ord(char):02x}" if char in CONTROL_CHARACTERS else char
        for char in text
    )


class ControlSafeFormatter(logging.Formatter):
    """A formatter that cannot write a tool's raw bytes into a log file.

    Tool output reaches log records through the values it produced, and a log
    file holding raw control bytes is a binary file: it stops being greppable
    and stops being reviewable.
    """

    def format(self, record: logging.LogRecord) -> str:
        return escape_control_characters(super().format(record))
