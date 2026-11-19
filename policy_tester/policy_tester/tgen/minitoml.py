"""tomllib が無い Python (3.10以下) 用の簡易TOMLパーサ。
このツール(vrouter_gen)が出力する範囲 (テーブル/配列テーブル/文字列/数値/真偽/配列/インラインテーブル) に対応。"""
import re


def loads(text):
    root = {}
    cur = root
    lines = text.lstrip("﻿").split("\n")
    i = 0
    while i < len(lines):
        line = _strip(lines[i]).strip()
        i += 1
        if not line:
            continue
        if line.startswith("[["):
            path = _path(line[2:line.index("]]")])
            cur = _table(root, path, array=True)
            continue
        if line.startswith("["):
            cur = _table(root, _path(line[1:line.index("]")]), array=False)
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        while _depth(v) > 0 and i < len(lines):   # 複数行の配列
            v += " " + _strip(lines[i]).strip()
            i += 1
        val, _ = _value(v, 0)
        cur[_key(k.strip())] = val
    return root


def _strip(s):
    out, q = [], False
    j = 0
    while j < len(s):
        c = s[j]
        if q and c == "\\":
            out.append(s[j:j + 2])
            j += 2
            continue
        if c == '"':
            q = not q
        if c == "#" and not q:
            break
        out.append(c)
        j += 1
    return "".join(out)


def _depth(v):
    d, q, j = 0, False, 0
    while j < len(v):
        c = v[j]
        if q and c == "\\":
            j += 2
            continue
        if c == '"':
            q = not q
        elif not q:
            d += c in "[{"
            d -= c in "]}"
        j += 1
    return d


def _key(k):
    return k[1:-1] if len(k) > 1 and k[0] == '"' else k


def _path(p):
    return [_key(x.strip()) for x in p.split(".")]


def _table(root, path, array):
    node = root
    for n, p in enumerate(path):
        last = n == len(path) - 1
        if last and array:
            node = node.setdefault(p, [])
            t = {}
            node.append(t)
            return t
        nxt = node.setdefault(p, {} if not isinstance(node.get(p), list) else node[p])
        node = nxt[-1] if isinstance(nxt, list) else nxt
    return node


_ESC = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


def _value(s, i):
    while s[i] == " ":
        i += 1
    c = s[i]
    if c == '"':
        j, out = i + 1, []
        while s[j] != '"':
            if s[j] == "\\":
                j += 1
                if s[j] == "u":
                    out.append(chr(int(s[j + 1:j + 5], 16)))
                    j += 4
                else:
                    out.append(_ESC.get(s[j], s[j]))
            else:
                out.append(s[j])
            j += 1
        return "".join(out), j + 1
    if c == "[":
        arr, i = [], i + 1
        while True:
            while s[i] in " ,":
                i += 1
            if s[i] == "]":
                return arr, i + 1
            v, i = _value(s, i)
            arr.append(v)
    if c == "{":
        d, i = {}, i + 1
        while True:
            while s[i] in " ,":
                i += 1
            if s[i] == "}":
                return d, i + 1
            m = re.compile(r'\s*("[^"]*"|[A-Za-z0-9_\-]+)\s*=').match(s, i)
            k = _key(m.group(1))
            d[k], i = _value(s, m.end())
    m = re.compile(r"[^,\]\}\s]+").match(s, i)
    tok = m.group(0)
    if tok == "true":
        return True, m.end()
    if tok == "false":
        return False, m.end()
    try:
        return int(tok.replace("_", "")), m.end()
    except ValueError:
        return float(tok), m.end()
