"""Karton PDFAnalyzer Service."""

import re
from collections.abc import Iterator
from typing import ClassVar, cast
from urllib.parse import urlparse

import requests
import tldextract
from karton.core import Karton, RemoteResource, Resource, Task
from quicksand.quicksand import quicksand

from .__version__ import __version__


class PDFAnalyzer(Karton):
    """
    Analyse a PDF file using Quicksand.

    For a given sample, we will analyze it using **Quicksand** and:
    1. Add the detected TTPs as **tags**
    2. Add the `risk`, TTPs and their related fields, and extracted urls to the sample as **attributes**
    3. Attempt to download any files from extracted URLs and produce them as new samples for further analysis.

    **Consumes:**
    ```
    {"type": "sample", "kind": "document" },
    ```

    **Produces:**
    ```
    {
        "headers": {"type": "sample", "stage": "analyzed"},
        "payload": {
            "sample": sample,
            "tags": <Mitre TTPs tags>,
            "attributes": {
                "quicksand": <Minimized Quicksand result>,
            }
        }
    }

    {
        "headers": {"type": "sample", "kind": "raw"},
        "payload": {
            "sample": new_resource,
            "parent": original_sample,
            "comments": "Downloaded from URL: <attempted_url>",
            }
        }
    }
    ```
    """

    identity = "karton.pdf_analyzer"
    filters: ClassVar = [
        {"type": "sample", "kind": "document" },
    ]
    version = __version__

    URL_RE = r"""
        (?:(?:(?:https?|ftp):)?\/\/)
        (?:\S+(?::\S*)?@)?
        (?:
            (?!(?:10|127)(?:\.\d{1,3}){3})
            (?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})
            (?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})
            (?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])
            (?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}
            (?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))
            |
            (?:(?:[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff_-]{0,62})?[a-z0-9\u00a1-\uffff]\.)+
            (?:[a-z\u00a1-\uffff]{2,}\.?)
        )
        (?::\d{2,5})?
        (?:[/?#][A-Za-z0-9\-._~%!$&'()*+,;=:@/?#]*)?
    """

    @staticmethod
    def extract_urls(content: str) -> list[str]:
        """
        Extract all URLs (optionally with ports) from the given text.

        Args:
            content (str): The input text to search for URLs.

        Returns:
            list[str]: A list of unique URLs addresses found in the content.

        """
        url_pattern = re.compile(PDFAnalyzer.URL_RE, re.VERBOSE | re.MULTILINE | re.IGNORECASE | re.DOTALL)
        url_matches = [match.group(0).strip() for match in url_pattern.finditer(content)]
        return list(set(url_matches))


    def fetch_url_with_variants(self, url: str) -> Iterator[tuple[str, bytes]]:
        """
        Yield content for all URL variants instead of stopping at the first success.

        In PDFs, sometimes URLs might be encapsulated in parenthesis, therefore we will
        attempt to fetch both the raw URL and the URL without surrounding parenthesis.

        Args:
            url (str): The URL to fetch.

        Yields:
            Iterator[tuple[str, bytes]]: An iterator over tuples containing the URL and its content.

        """
        urls_to_try = [url]

        # Remove surrounding parentheses if present
        if url.endswith(")"):
            urls_to_try.append(url[:-1])

        for attempt_url in urls_to_try:
            try:
                self.log.info(f"Attempting to fetch URL: {attempt_url}")
                response = requests.get(
                    attempt_url,
                    timeout=30,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    },
                    allow_redirects=True,
                    verify=True,
                )

                if response.status_code == requests.codes.ok:
                    self.log.info(f"Successfully fetched URL: {attempt_url} ({len(response.content)} bytes)")
                    yield attempt_url, response.content
                else:
                    self.log.warning(f"Failed to fetch URL: {attempt_url} (status code: {response.status_code})")

            except requests.exceptions.RequestException as e:
                self.log.warning(f"Error fetching URL {attempt_url}: {e!s}")
                continue


    def process(self, task: Task) -> None:  # noqa: C901
        """
        Entry point of this service.

        Analyze a PDF file.

        Args:
            task (Task): Karton task

        """
        sample_resource = cast("RemoteResource", task.get_resource("sample"))

        with sample_resource.download_temporary_file() as f:
            qs = quicksand(f.name, capture=True, strings=True, timeout=60)
            qs.process()
            quicksand_analysis = qs.results.get("results", {})

        if not quicksand_analysis:
            return

        self.log.info(f"Successfully analyzed PDF {sample_resource.sha256} with Quicksand")

        risk = qs.results.get("risk", "N/A")
        mitre_ttps = set()
        analysis = []

        for results in quicksand_analysis.values():
            for result in results:
                ttps: list[str] = result.get("mitre", "").split(" ")
                ttps = [ttp.strip().lower()for ttp in ttps if ttp.strip()]
                mitre_ttps.update(ttps)

                analysis.append({
                    "description": result.get("desc", "N/A"),
                    "strings": result.get("strings", "N/A"),
                    "mitre": result.get("mitre", "N/A"),
                })

        all_content = ""
        quicksand_content = qs.results.get("streams", {})
        if quicksand_content:
            for stream in quicksand_content.values():
                all_content += stream.decode("utf-8", errors="replace")

        urls = PDFAnalyzer.extract_urls(all_content)

        if risk == "N/A" and not mitre_ttps:
            self.log.info(f"No significant findings for PDF {sample_resource.sha256}, skipping further processing.")
        else:
            self.send_task(
                Task(
                    headers={"type": "sample", "stage": "analyzed"},
                    payload={
                        "sample": sample_resource,
                        "tags": list(mitre_ttps),
                        "attributes": {
                            "quicksand": [{
                                "analysis": analysis,
                                "risk": [risk],
                                "extracted_urls": urls,
                            }],
                        },
                    },
                ),
            )

        for url in urls:
            extracted = tldextract.extract(url)
            # Skip private/local URLs
            if extracted.is_private:
                self.log.info(f"Skipping private URL: {url}")
                continue
            parsed = urlparse(url)
            # Skip URLs without proper structure
            if not parsed.scheme or not parsed.netloc or not parsed.path or parsed.path == "/":
                self.log.info(f"Skipping malformed or incomplete URL: {url}")
                continue

            for attempt_url, content in self.fetch_url_with_variants(url):
                    parsed = urlparse(attempt_url)
                    resource = Resource(
                        name=parsed.path.split("/")[-1] or "downloaded_file",
                        content=content,
                    )
                    self.send_task(
                        Task(
                            headers={"type": "sample", "kind": "raw"},
                            payload={
                                "sample": resource,
                                "parent": sample_resource,
                                "comments": [f"Downloaded from URL: {attempt_url}"],
                            },
                        ),
                    )
