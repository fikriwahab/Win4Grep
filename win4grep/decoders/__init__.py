# Decoder registry. Importing this package registers all decoders in priority
# order (first to sniff True wins), TextDecoder is the explicit fallback
from __future__ import annotations

from .base import Decoder, pick, register, registry  # noqa: F401

# import order == dispatch priority (first decoder whose sniff() returns True wins)
from . import mobileprovision_decoder  # noqa: F401,E402  (specific extension)
from . import macho_decoder            # noqa: F401,E402  (magic bytes)
from . import plist_decoder            # noqa: F401,E402
from . import sqlite_decoder           # noqa: F401,E402
from . import cookies_decoder          # noqa: F401,E402
from . import protobuf_decoder         # noqa: F401,E402
from . import realm_decoder            # noqa: F401,E402
from . import leveldb_decoder          # noqa: F401,E402
from . import graphql_decoder          # noqa: F401,E402  (.jsbundle/.js)
from . import text_decoder             # noqa: F401,E402  (fallback)

from .text_decoder import TextDecoder  # noqa: E402

FALLBACK = TextDecoder()
