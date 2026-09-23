"""Keysyms for keyEvent, from X11 keysymdef.h as RFB specifies."""


class Key:
    """The keysym constants a client is most likely to send.

    Printable ASCII characters use their ASCII value as the keysym, so only
    the named keys need constants here.
    """

    BACKSPACE = 0xFF08
    TAB = 0xFF09
    RETURN = 0xFF0D
    ESCAPE = 0xFF1B
    INSERT = 0xFF63
    DELETE = 0xFFFF
    HOME = 0xFF50
    END = 0xFF57
    PAGE_UP = 0xFF55
    PAGE_DOWN = 0xFF56
    LEFT = 0xFF51
    UP = 0xFF52
    RIGHT = 0xFF53
    DOWN = 0xFF54
    F1 = 0xFFBE
    F2 = 0xFFBF
    F3 = 0xFFC0
    F4 = 0xFFC1
    F5 = 0xFFC2
    F6 = 0xFFC3
    F7 = 0xFFC4
    F8 = 0xFFC5
    F9 = 0xFFC6
    F10 = 0xFFC7
    F11 = 0xFFC8
    F12 = 0xFFC9
    SHIFT = 0xFFE1
    CONTROL = 0xFFE3
    META = 0xFFE7
    ALT = 0xFFE9
