import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from collections import deque


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "inputs": [],
            }
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append(
                {
                    "name": attrs.get("name"),
                    "type": attrs.get("type", "text"),
                }
            )
        elif tag == "textarea" and self.current_form is not None:
            self.current_form["inputs"].append(
                {
                    "name": attrs.get("name"),
                    "type": "textarea",
                }
            )
        elif tag == "select" and self.current_form is not None:
            self.current_form["inputs"].append(
                {
                    "name": attrs.get("name"),
                    "type": "select",
                }
            )
        elif tag == "a":
            href = attrs.get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def parse(self, html):
        self.links = []
        self.forms = []
        self.current_form = None
        self.feed(html)
        return self.links, self.forms


def fetch(url):
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode('utf-8', errors='replace')


def crawl(start_url, limit=10):
    visited = set()
    queue = deque([start_url])
    results = {}
    parser = FormParser()

    while queue and len(visited) < limit:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            html = fetch(url)
        except Exception:
            continue
        links, forms = parser.parse(html)
        abs_forms = []
        for form in forms:
            form_copy = form.copy()
            form_copy["action"] = urljoin(url, form.get("action", ""))
            abs_forms.append(form_copy)
        results[url] = {
            "links": links,
            "forms": abs_forms,
        }
        for link in links:
            absolute = urljoin(url, link)
            if urlparse(absolute).netloc == urlparse(start_url).netloc:
                if absolute not in visited:
                    queue.append(absolute)
    return results
