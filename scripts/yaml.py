"""Minimal stand-in for PyYAML on hosts where packages cannot be installed.

netauto.py only ever calls yaml.safe_load(), so that is all this provides: the
subset of YAML an inventory needs - nested mappings, block sequences, scalars
and comments - read with the standard library alone.

A yaml.py in scripts/, beside the modules that import it, shadows an installed
PyYAML for anything run from there. That shadowing is deliberate. The offline
audit path is the deployment target, not a fallback, so the inventory has to
parse the same way on a locked-down work machine as it does on a developer's
box: one parser everywhere means a file that loads at work loads here too.

JSON is still read, and is tried first - it is a subset of YAML 1.2, and every
inventory written before this file could parse YAML is JSON.

What this does NOT support - anchors, aliases, tags, block scalars, multiple
documents, non-empty inline collections, sequences of mappings - raises
YAMLError naming the line, rather than being guessed at. A quietly mis-read
inventory is the worst failure available to this repo: it does not look like
an error, it looks like a compliance verdict.
"""

import json


class YAMLError(ValueError):
    """Raised for input this parser will not guess at."""


def safe_load(stream):
    text = stream.read() if hasattr(stream, 'read') else stream
    try:
        return json.loads(text)
    except ValueError:
        pass
    lines = _scan(text)
    if not lines:
        return None
    value, index = _parse_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise YAMLError(_at(lines[index], 'unexpected indentation'))
    return value


def _scan(text):
    """Drop blanks and comments; return (indent, content, lineno) per real line."""
    scanned = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        bare = raw.strip()
        if bare == '...':
            continue
        if bare == '---':
            if scanned:
                raise YAMLError('line %d: more than one document in one file' % lineno)
            continue
        content = _strip_comment(raw, lineno)
        if not content.strip():
            continue
        leading = content[:len(content) - len(content.lstrip(' \t'))]
        if '\t' in leading:
            raise YAMLError('line %d: tab in indentation - YAML wants spaces' % lineno)
        body = content.lstrip(' ')
        indent = len(content) - len(body)
        scanned.append((indent, body.rstrip(), lineno))
    return scanned


def _strip_comment(raw, lineno):
    """Cut a trailing `# comment`, but not a '#' inside a quoted scalar."""
    kept = []
    quote = None
    index = 0
    while index < len(raw):
        char = raw[index]
        if quote:
            if char == '\\' and quote == '"' and index + 1 < len(raw):
                kept.append(char)
                kept.append(raw[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in '"\'':
            quote = char
        elif char == '#' and (index == 0 or raw[index - 1] in ' \t'):
            break
        kept.append(char)
        index += 1
    if quote:
        raise YAMLError('line %d: unterminated %s quote' % (lineno, quote))
    return ''.join(kept)


def _parse_block(lines, index, indent):
    content = lines[index][1]
    if content == '-' or content.startswith('- '):
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_mapping(lines, index, indent):
    mapping = {}
    while index < len(lines):
        line_indent, content, lineno = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise YAMLError(_at(lines[index], 'unexpected indentation'))
        if content == '-' or content.startswith('- '):
            raise YAMLError(_at(lines[index], 'list item where a "key: value" was expected'))
        key, rest = _split_key(content, lineno)
        index += 1
        if rest.strip():
            value = _scalar(rest, lineno)
        elif index < len(lines) and lines[index][0] > line_indent:
            value, index = _parse_block(lines, index, lines[index][0])
        elif (index < len(lines) and lines[index][0] == line_indent
                and (lines[index][1] == '-' or lines[index][1].startswith('- '))):
            # A sequence may sit at its key's own indent, which is common enough
            # in hand-written YAML that refusing it would read as a parser bug.
            value, index = _parse_sequence(lines, index, line_indent)
        else:
            value = None
        if key in mapping:
            raise YAMLError('line %d: duplicate key %r' % (lineno, key))
        mapping[key] = value
    return mapping, index


def _parse_sequence(lines, index, indent):
    sequence = []
    while index < len(lines):
        line_indent, content, lineno = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise YAMLError(_at(lines[index], 'unexpected indentation'))
        if not (content == '-' or content.startswith('- ')):
            break
        item = content[1:].strip()
        index += 1
        if not item:
            if index < len(lines) and lines[index][0] > line_indent:
                value, index = _parse_block(lines, index, lines[index][0])
            else:
                value = None
        else:
            if _has_key_separator(item):
                raise YAMLError('line %d: a list of mappings is not supported here - '
                                'write it as a mapping: %r' % (lineno, content))
            value = _scalar(item, lineno)
        sequence.append(value)
    return sequence, index


def _split_key(content, lineno):
    position = _key_separator(content)
    if position is None:
        raise YAMLError('line %d: expected "key: value", got %r' % (lineno, content))
    return _unquote(content[:position].strip(), lineno), content[position + 1:]


def _has_key_separator(text):
    return _key_separator(text) is not None


def _key_separator(text):
    """Index of the ':' splitting key from value, ignoring ones inside quotes."""
    quote = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in '"\'':
            quote = char
        elif char == ':' and (index + 1 == len(text) or text[index + 1] == ' '):
            return index
    return None


def _scalar(text, lineno):
    text = text.strip()
    if text == '[]':
        return []
    if text == '{}':
        return {}
    if text[:1] in ('[', '{'):
        raise YAMLError('line %d: inline collections are supported only when empty '
                        '([] or {}) - write it as an indented block' % lineno)
    if text[:1] in ('&', '*', '!'):
        raise YAMLError('line %d: anchors, aliases and tags are not supported' % lineno)
    if text[:1] in ('|', '>'):
        raise YAMLError('line %d: block scalars are not supported' % lineno)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in '"\'':
        return _unquote(text, lineno)
    lowered = text.lower()
    if lowered in ('null', '~'):
        return None
    if lowered == 'true':
        return True
    if lowered == 'false':
        return False
    for cast in (int, float):
        try:
            return cast(text)
        except ValueError:
            pass
    return text


def _unquote(text, lineno):
    if len(text) >= 2 and text[0] == text[-1] and text[0] in '"\'':
        body = text[1:-1]
        if text[0] == '"':
            return body.replace('\\n', '\n').replace('\\"', '"').replace('\\\\', '\\')
        return body.replace("''", "'")
    if text[:1] in ('"', "'"):
        raise YAMLError('line %d: unterminated quote in %r' % (lineno, text))
    return text


def _at(line, message):
    return 'line %d: %s: %r' % (line[2], message, line[1])
