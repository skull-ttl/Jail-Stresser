"""Import a target from a copied cURL command (PUBLIC harness).

Flow: the user copies the real chat request from their browser (devtools ->
Network -> right-click -> Copy as cURL) and pastes it. We parse out method,
URL, headers (cookies included), and body, auto-detect which body field carries
the message, and build an adapter that replays that exact request - substituting
each attack payload into the detected field. This is the clean path for custom
apps behind sessions/cookies where detection+guessing would fail.

Also provides a universal RESPONSE extractor that handles the common shapes:
  - SSE  (data: {json} lines, incl. a 'final'/'done' convention)
  - plain JSON (OpenAI-style and other common key paths)
  - JSON-lines (one JSON object per line)
  - raw text
so the same import works against differently-behaving webapps.
"""

from __future__ import annotations

import json
import re
import shlex


# ---- cURL parsing ----------------------------------------------------------

def _decode_ansi_c(s: str) -> str:
    """Decode a bash ANSI-C $'...' string body: turn literal \\r \\n \\t \\' etc.
    into their real characters. This is what bash does before sending, so the
    server receives real CRLFs (critical for multipart bodies)."""
    replacements = {
        r"\r": "\r", r"\n": "\n", r"\t": "\t", r"\\": "\\",
        r"\'": "'", r'\"': '"', r"\a": "\a", r"\b": "\b",
        r"\f": "\f", r"\v": "\v", r"\0": "\0",
    }
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            two = s[i:i+2]
            if two in replacements:
                out.append(replacements[two])
                i += 2
                continue
        out.append(s[i])
        i += 1
    return "".join(out)


def parse_curl(curl_text: str) -> dict:
    """Parse a 'Copy as cURL' string into {method, url, headers, body}.
    Tolerant of line continuations, $'...' ANSI-C quoting (incl. escape
    decoding, needed for multipart bodies), and --data variants."""
    text = curl_text.replace("\\\n", " ").replace("\r", " ").replace("\n", " ").strip()

    # Pre-extract $'...' ANSI-C quoted segments, decode their escapes, and stash
    # them as placeholders so shlex doesn't mangle them. Firefox uses this form
    # for binary/multipart bodies.
    ansi_segments = []
    def _stash(m):
        decoded = _decode_ansi_c(m.group(1))
        ansi_segments.append(decoded)
        return f"\x00ANSI{len(ansi_segments)-1}\x00"
    text = re.sub(r"\$'((?:[^'\\]|\\.)*)'", _stash, text)

    try:
        tokens = shlex.split(text)
    except ValueError:
        tokens = text.split()

    def _unstash(tok):
        m = re.fullmatch(r"\x00ANSI(\d+)\x00", tok)
        if m:
            return ansi_segments[int(m.group(1))]
        # token may contain the placeholder embedded
        return re.sub(r"\x00ANSI(\d+)\x00",
                      lambda mm: ansi_segments[int(mm.group(1))], tok)

    tokens = [_unstash(t) for t in tokens]

    method = None
    url = None
    headers = {}
    body = None

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t == "curl":
            i += 1; continue
        if t in ("-X", "--request"):
            method = tokens[i + 1]; i += 2; continue
        if t in ("-H", "--header"):
            h = tokens[i + 1]
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2; continue
        if t in ("-b", "--cookie"):
            headers["Cookie"] = tokens[i + 1]; i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
            body = tokens[i + 1]; i += 2; continue
        if t in ("--compressed", "-s", "--silent", "-k", "--insecure",
                 "-i", "--include", "-L", "--location"):
            i += 1; continue
        if t in ("-A", "--user-agent"):
            headers["User-Agent"] = tokens[i + 1]; i += 2; continue
        if t in ("-e", "--referer"):
            headers["Referer"] = tokens[i + 1]; i += 2; continue
        if not t.startswith("-") and url is None:
            url = t
        i += 1

    if method is None:
        method = "POST" if body is not None else "GET"
    return {"method": method.upper(), "url": url, "headers": headers, "body": body}


def find_injection_field(body: str, probe_value_hint: str = None):
    """Given a JSON body, return (parsed_obj, dotted_path_to_message_field).
    We locate the field whose value looks like the user's typed message so we
    know where to substitute attack payloads. Heuristics: a value matching the
    probe hint, else common field names, else the first string value."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None, None

    candidates_by_name = ("message", "prompt", "content", "text", "input", "query", "q")

    # 1) value equal to the hint (e.g. what the user typed when capturing)
    def walk(o, path):
        if isinstance(o, dict):
            for k, v in o.items():
                yield from walk(v, path + [k])
        elif isinstance(o, list):
            for idx, v in enumerate(o):
                yield from walk(v, path + [str(idx)])
        else:
            yield path, o

    leaves = list(walk(obj, []))
    if probe_value_hint:
        for path, val in leaves:
            if isinstance(val, str) and val.strip() == probe_value_hint.strip():
                return obj, ".".join(path)
    # 2) common field name
    for path, val in leaves:
        if path and path[-1].lower() in candidates_by_name and isinstance(val, str):
            return obj, ".".join(path)
    # 3) first string leaf
    for path, val in leaves:
        if isinstance(val, str):
            return obj, ".".join(path)
    return obj, None


def set_by_path(obj, dotted_path, value):
    """Return a deep-ish copy of obj with dotted_path set to value."""
    import copy
    out = copy.deepcopy(obj)
    cur = out
    parts = dotted_path.split(".")
    for p in parts[:-1]:
        if isinstance(cur, list):
            cur = cur[int(p)]
        else:
            cur = cur[p]
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value
    return out


# ---- format-agnostic body handling -----------------------------------------
# Real AI apps post bodies in many shapes: JSON, multipart/form-data, urlencoded
# forms, or plain text. BodyTemplate detects which, locates the injectable field
# the same way regardless, and rebuilds the body in the SAME format with the
# attack payload substituted. This is what lets the tool target arbitrary apps.

_COMMON_FIELD_NAMES = ("prompt", "message", "content", "text", "input", "query",
                       "q", "question", "msg", "user_input")
# Fields that are clearly NOT the message (config/control fields), so we don't
# inject into them by mistake when there are several.
_NON_MESSAGE_FIELDS = ("defender", "model", "session", "sid", "token", "role",
                       "stream", "temperature", "max_tokens", "system")


def _looks_multipart(content_type: str, body: str) -> bool:
    if "multipart/form-data" in (content_type or "").lower():
        return True
    return bool(re.search(r"Content-Disposition:\s*form-data;\s*name=", body or "",
                          re.IGNORECASE))


def _looks_urlencoded(content_type: str, body: str) -> bool:
    if "application/x-www-form-urlencoded" in (content_type or "").lower():
        return True
    # heuristic: key=value&key=value with no JSON/multipart markers
    if body and "=" in body and "&" in body and not body.strip().startswith("{") \
       and "Content-Disposition" not in body:
        return True
    return False


class BodyTemplate:
    """Parses a request body of unknown format and rebuilds it with a payload
    substituted into the detected injectable field. Formats: json, multipart,
    urlencoded, raw."""

    def __init__(self, body: str, content_type: str = "", probe_hint: str = None):
        self.raw = body or ""
        self.content_type = content_type or ""
        self.probe_hint = probe_hint
        self.format = "raw"
        self.field = None
        self._json_obj = None
        self._multipart_boundary = None
        self._multipart_fields = None   # list of (name, value, is_file_headerblock)
        self._url_pairs = None
        self._detect()

    # -- detection ----------------------------------------------------------
    def _detect(self):
        body = self.raw
        # JSON
        if body.strip().startswith("{") or body.strip().startswith("["):
            try:
                self._json_obj = json.loads(body)
                self.format = "json"
                _, self.field = find_injection_field(body, self.probe_hint)
                return
            except json.JSONDecodeError:
                pass
        # multipart
        if _looks_multipart(self.content_type, body):
            self._parse_multipart()
            if self._multipart_fields is not None:
                self.format = "multipart"
                self.field = self._pick_field([n for n, _ in self._multipart_fields])
                return
        # urlencoded
        if _looks_urlencoded(self.content_type, body):
            self._url_pairs = [tuple(p.split("=", 1)) if "=" in p else (p, "")
                               for p in body.split("&")]
            self.format = "urlencoded"
            self.field = self._pick_field([k for k, _ in self._url_pairs])
            return
        # raw fallback
        self.format = "raw"
        self.field = None

    def _pick_field(self, names):
        """Choose the injectable field among several form fields."""
        # 1) a field whose captured value equals the probe hint
        if self.probe_hint:
            if self.format == "multipart":
                for n, v in self._multipart_fields:
                    if v.strip() == self.probe_hint.strip():
                        return n
            elif self.format == "urlencoded":
                for k, v in self._url_pairs:
                    if v.strip() == self.probe_hint.strip():
                        return k
        # 2) a common message field name, skipping known control fields
        lowered = {n.lower(): n for n in names}
        for cand in _COMMON_FIELD_NAMES:
            if cand in lowered:
                return lowered[cand]
        # 3) the first field that isn't a known control field
        for n in names:
            if n.lower() not in _NON_MESSAGE_FIELDS:
                return n
        return names[0] if names else None

    def _parse_multipart(self):
        body = self.raw
        # boundary: from content-type, else infer from the body's leading ----...
        m = re.search(r"boundary=([^\s;]+)", self.content_type)
        if m:
            boundary = m.group(1)
        else:
            bm = re.match(r"\s*(--+[A-Za-z0-9'\-]+)", body)
            if not bm:
                return
            boundary = bm.group(1).lstrip("-")
        self._multipart_boundary = boundary
        # split into parts on the boundary delimiter
        delim = "--" + boundary
        chunks = body.split(delim)
        fields = []
        for ch in chunks:
            # don't strip the whole chunk first - that can eat the value's own
            # trailing chars; only trim the leading CRLF after the delimiter.
            if not ch.strip() or ch.strip() == "--":
                continue
            nm = re.search(r'name="([^"]+)"', ch)
            if not nm:
                continue
            name = nm.group(1)
            # value is everything after the blank line separating headers from
            # content, with only the trailing CRLF (before the next boundary)
            # removed - inner content is preserved verbatim.
            parts = re.split(r"\r?\n\r?\n", ch, maxsplit=1)
            if len(parts) > 1:
                value = parts[1]
                # strip exactly one trailing CRLF that precedes the boundary
                value = re.sub(r"\r?\n$", "", value)
            else:
                value = ""
            fields.append((name, value))
        self._multipart_fields = fields

    # -- rebuild ------------------------------------------------------------
    def build(self, payload: str) -> tuple:
        """Return (body_bytes_or_str, content_type_override_or_None)."""
        if self.format == "json" and self.field:
            return json.dumps(set_by_path(self._json_obj, self.field, payload)), None
        if self.format == "multipart" and self.field:
            return self._build_multipart(payload), \
                f"multipart/form-data; boundary={self._multipart_boundary}"
        if self.format == "urlencoded" and self.field:
            from urllib.parse import quote
            pairs = []
            for k, v in self._url_pairs:
                nv = payload if k == self.field else v
                pairs.append(f"{k}={quote(str(nv))}")
            return "&".join(pairs), "application/x-www-form-urlencoded"
        # raw: substitute the probe hint if known, else append payload
        if self.probe_hint and self.probe_hint in self.raw:
            return self.raw.replace(self.probe_hint, payload, 1), None
        return (self.raw + payload) if self.raw else payload, None

    def _build_multipart(self, payload: str) -> str:
        b = self._multipart_boundary
        out = []
        for name, value in self._multipart_fields:
            nv = payload if name == self.field else value
            out.append(f"--{b}\r\n"
                       f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                       f"{nv}\r\n")
        out.append(f"--{b}--\r\n")
        return "".join(out)

    def describe(self) -> str:
        if self.field:
            return f"{self.format} body, inject into field '{self.field}'"
        return f"{self.format} body (no field detected; raw substitution)"


# ---- universal response extraction -----------------------------------------

def extract_reply(raw_text: str, content_type: str = "") -> str:
    """Extract the assistant's reply text from a response of unknown shape.
    Handles SSE, plain JSON (common key paths), JSON-lines, and raw text."""
    if raw_text is None:
        return ""
    body = raw_text.strip()
    if not body:
        return ""

    # 1) SSE: lines beginning with 'data:'
    if "data:" in body and re.search(r"^\s*data:", body, re.MULTILINE):
        return _extract_sse(body)

    # 2) single JSON object/array
    try:
        obj = json.loads(body)
        got = _extract_from_json(obj)
        if got is not None:
            return got
    except json.JSONDecodeError:
        pass

    # 3) JSON-lines: one object per line, concatenate token-ish fields
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if len(lines) > 1 and all(ln.strip().startswith("{") for ln in lines[:3]):
        acc = []
        final = None
        for ln in lines:
            try:
                o = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if isinstance(o, dict):
                if o.get("type") == "final" and "data" in o:
                    final = o["data"]
                got = _extract_from_json(o)
                if got:
                    acc.append(got)
        if final is not None:
            return final
        if acc:
            return "".join(acc)

    # 4) raw text fallback
    return body


def _extract_sse(body: str) -> str:
    """Parse Server-Sent Events. Prefer a 'final' event; else concat tokens."""
    final = None
    tokens = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if payload in ("[DONE]", ""):
            continue
        try:
            o = json.loads(payload)
        except json.JSONDecodeError:
            tokens.append(payload)  # raw text token
            continue
        if isinstance(o, dict):
            typ = o.get("type")
            if typ == "final" and "data" in o:
                final = o["data"]
            elif typ == "token" and "data" in o:
                tokens.append(o["data"])
            elif typ == "done":
                continue
            else:
                # OpenAI streaming delta shape
                got = _extract_from_json(o)
                if got:
                    tokens.append(got)
    if final is not None:
        return final
    return "".join(tokens)


_JSON_PATHS = (
    ("choices", 0, "message", "content"),      # OpenAI chat
    ("choices", 0, "delta", "content"),         # OpenAI stream delta
    ("choices", 0, "text"),                     # OpenAI completions
    ("message", "content"),                     # ollama /api/chat
    ("response",),                              # ollama /api/generate
    ("content",),
    ("text",),
    ("reply",),
    ("answer",),
    ("data",),
    ("output",),
)


def _extract_from_json(obj):
    if isinstance(obj, str):
        return obj
    if not isinstance(obj, (dict, list)):
        return None
    for path in _JSON_PATHS:
        cur = obj
        ok = True
        for key in path:
            try:
                cur = cur[key]
            except (KeyError, IndexError, TypeError):
                ok = False
                break
        if ok and isinstance(cur, str):
            return cur
    return None
