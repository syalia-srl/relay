#!/usr/bin/env python3
"""Build the relay documentation site from Markdown into docs/_site.

Every page is rendered from one Markdown source through docs/tools/template.html.
PROTOCOL.md and SECURITY.md are included unchanged. The build also writes the .md
twin of every page, llms.txt, and fails on a broken internal link.
"""

from __future__ import annotations

import html
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

try:
    import markdown
except ImportError:  # pragma: no cover - the docs dependency group provides it
    sys.exit("the docs dependency group is missing: uv run --group docs python docs/tools/build.py")

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
SRC = DOCS / "src"
OUT = DOCS / "_site"

PAGES = [
    {
        "slug": "run-a-relay",
        "source": SRC / "run-a-relay.md",
        "title": "Running a relay",
        "summary": "the relay as one static Go binary: systemd, Caddy with TLS, keys.json, checks, upgrades and state.",
    },
    {
        "slug": "protocol",
        "source": ROOT / "PROTOCOL.md",
        "title": "Protocol",
        "summary": "the normative relay API v1 and channel protocol v3: layers, routes, handshakes, frames and control messages.",
    },
    {
        "slug": "security",
        "source": ROOT / "SECURITY.md",
        "title": "Security",
        "summary": "the threat model: what the code promises, which adversaries it considers, and what it does not do.",
    },
    {
        "slug": "python",
        "source": SRC / "python.md",
        "title": "Python",
        "summary": "the Python host and guest: install, pairing, sending, stores, errors and a worked echo example.",
    },
    {
        "slug": "javascript",
        "source": SRC / "javascript.md",
        "title": "JavaScript",
        "summary": "the JavaScript host and guest for Node and browsers: install, pairing, stores, errors and a worked echo example.",
    },
    {
        "slug": "go",
        "source": SRC / "go.md",
        "title": "Go",
        "summary": "the Go host and guest: install, pairing, stores, errors and a worked echo example.",
    },
]

NAV = [
    ("index.html", "Overview"),
    ("run-a-relay.html", "Run a relay"),
    ("protocol.html", "Protocol"),
    ("security.html", "Security"),
    ("python.html", "Python"),
    ("javascript.html", "JavaScript"),
    ("go.html", "Go"),
]

INCLUDE = re.compile(r"^<!--\s*include:\s*(\S+)\s+(\S+)\s*-->$", re.MULTILINE)
LINK_HTML = re.compile(r"""<a\s[^>]*href="([^"]+)\"""", re.IGNORECASE)
LINK_MD = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
ID = re.compile(r"""\bid="([^"]+)\"""")
FENCE = re.compile(r"^```.*?^```$", re.MULTILINE | re.DOTALL)


def expand_includes(text: str) -> str:
    """Replace each include marker with a fenced block holding the file verbatim."""

    def replace(match: re.Match[str]) -> str:
        path = (ROOT / match.group(1)).resolve()
        if ROOT not in path.parents and path != ROOT:
            raise SystemExit(f"include outside the repository: {match.group(1)}")
        if not path.is_file():
            raise SystemExit(f"include not found: {match.group(1)}")
        body = path.read_text(encoding="utf-8").rstrip("\n")
        if "```" in body:
            raise SystemExit(f"include contains a code fence: {match.group(1)}")
        return f"```{match.group(2)}\n{body}\n```"

    return INCLUDE.sub(replace, text)


def twin(text: str) -> str:
    """Point a page's Markdown twin at the other twins, not at the HTML pages."""

    def replace(match: re.Match[str]) -> str:
        href = match.group(1)
        if href.startswith(("http://", "https://", "mailto:", "#", "/")):
            return match.group(0)
        path, sep, fragment = href.partition("#")
        if path.endswith(".html"):
            path = path[:-5] + ".md"
            return match.group(0).replace(href, path + (sep + fragment if sep else ""))
        return match.group(0)

    return LINK_MD.sub(replace, text)


def render(text: str) -> tuple[str, str]:
    renderer = markdown.Markdown(
        extensions=["extra", "toc", "sane_lists"],
        extension_configs={
            "toc": {"permalink": "¶", "toc_depth": "2-3", "anchorlink": False},
        },
    )
    body = renderer.convert(text)
    body = re.sub(r"<table>.*?</table>", lambda m: f'<div class="table-scroll">{m.group(0)}</div>',
                  body, flags=re.DOTALL)
    body = re.sub(r"<pre>.*?</pre>", lambda m: f'<div class="code-wrap">{m.group(0)}</div>',
                  body, flags=re.DOTALL)
    body = re.sub(r'(<h1[^>]*>)(.*?)<a class="headerlink".*?</a>', r"\1\2", body,
                  count=1, flags=re.DOTALL)
    return body, renderer.toc


def title_of(text: str, fallback: str) -> str:
    match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
    return html.unescape(match.group(1).strip()) if match else fallback


def navigation(current: str) -> str:
    links = []
    for href, label in NAV:
        current_attr = ' aria-current="page"' if href == current else ""
        links.append(f'<a href="{href}"{current_attr}>{label}</a>')
    links.append('<a href="https://github.com/syalia-srl/relay">GitHub</a>')
    return "\n      ".join(links)


def llms() -> str:
    lines = [
        "# Relay",
        "",
        "The relay and channel protocol of syalia-srl/relay: two-sided channels that carry "
        "end-to-end encrypted frames a relay cannot read.",
        "",
        "## Documentation",
        "",
        "- [Overview](index.md): what the relay and the channel protocol are, with links to every page.",
    ]
    for page in PAGES:
        lines.append(f"- [{page['title']}]({page['slug']}.md): {page['summary']}")
    lines += [
        "- [llms.txt](llms.txt): this index.",
        "",
        "## Tests",
        "",
        "- [Test vectors](https://github.com/syalia-srl/relay/tree/main/vectors): JSON cases that pin the handshake, "
        "transport, rekey and pairing-code bytes.",
        "- [Conformance suite](https://github.com/syalia-srl/relay/tree/main/conformance): a black-box suite that starts "
        "a relay and checks the v0 behaviour and every v1 rule.",
        "",
        "## Source",
        "",
        "- [Repository](https://github.com/syalia-srl/relay): the relay server, PROTOCOL.md, SECURITY.md and the three libraries.",
        "",
        "Every page above has an HTML version at the same path with `.html` in place of `.md`.",
        "",
    ]
    return "\n".join(lines)


def check_links(files: list[Path]) -> list[str]:
    broken = []
    ids: dict[Path, set[str]] = {}
    for path in files:
        if path.suffix == ".html":
            ids[path] = set(ID.findall(path.read_text(encoding="utf-8")))
    for path in files:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".md":
            text = FENCE.sub("", text)
            links = LINK_MD.findall(text)
        elif path.suffix == ".html":
            links = LINK_HTML.findall(text)
        else:
            continue
        for raw in links:
            href = html.unescape(raw)
            parts = urlsplit(href)
            if parts.scheme or parts.netloc or href.startswith("//"):
                continue
            target = unquote(parts.path)
            if not target:
                target_path = path
            else:
                target_path = (path.parent / target).resolve()
                if target.endswith("/"):
                    target_path = target_path / "index.html"
            if not target_path.exists() or not target_path.is_file():
                broken.append(f"{path.relative_to(OUT)} -> {href}")
                continue
            if parts.fragment:
                if target_path.suffix == ".html":
                    known = ids.get(target_path, set(ID.findall(target_path.read_text(encoding="utf-8"))))
                else:
                    known = set()
                if parts.fragment not in known and target_path.suffix == ".html":
                    broken.append(f"{path.relative_to(OUT)} -> {href} (missing anchor)")
    return broken


def main() -> int:
    for page in PAGES:
        if not page["source"].is_file():
            raise SystemExit(f"missing source: {page['source']}")
    template = (DOCS / "tools" / "template.html").read_text(encoding="utf-8")
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    written = 0
    for page in PAGES:
        source = expand_includes(page["source"].read_text(encoding="utf-8"))
        plain = twin(source)
        body, toc = render(source)
        title = title_of(source, page["title"])
        html_page = (
            template.replace("@@TITLE@@", html.escape(title))
            .replace("@@DESCRIPTION@@", html.escape(page["summary"]))
            .replace("@@NAV@@", navigation(f"{page['slug']}.html"))
            .replace("@@TOC@@", toc)
            .replace("@@SLUG@@", page["slug"])
            .replace("@@CONTENT@@", body)
        )
        (OUT / f"{page['slug']}.html").write_text(
            f"<!-- generated by docs/tools/build.py from {page['source'].relative_to(ROOT)}; do not edit -->\n"
            + html_page,
            encoding="utf-8",
        )
        (OUT / f"{page['slug']}.md").write_text(plain, encoding="utf-8")
        written += 2

    landing = DOCS / "index.html"
    if not landing.is_file():
        raise SystemExit("missing docs/index.html")
    landing_text = landing.read_text(encoding="utf-8")
    index_source = expand_includes((SRC / "index.md").read_text(encoding="utf-8"))
    (OUT / "index.html").write_text(landing_text, encoding="utf-8")
    (OUT / "index.md").write_text(twin(index_source), encoding="utf-8")
    written += 2

    shutil.copy2(DOCS / "CNAME", OUT / "CNAME")
    shutil.copy2(DOCS / "favicon.svg", OUT / "favicon.svg")
    (OUT / "llms.txt").write_text(llms(), encoding="utf-8")

    missing = [f"{page['slug']}.html" for page in PAGES
               if f"{page['slug']}.html" not in landing_text]
    if missing:
        raise SystemExit("the landing page does not link to: " + ", ".join(missing))

    files = sorted(OUT.rglob("*"))
    docs = [path for path in files if path.suffix in (".html", ".md")]
    broken = check_links(docs)
    if broken:
        print("broken internal links:")
        for line in broken:
            print("  " + line)
        return 1
    print(f"{len(PAGES)} pages, {len(PAGES)} Markdown twins, landing and llms.txt in {OUT.relative_to(ROOT)}")
    print(f"{written} files written, {len(docs)} checked, 0 broken links")
    return 0


if __name__ == "__main__":
    sys.exit(main())
