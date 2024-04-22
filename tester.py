import unittest
from bs4 import BeautifulSoup
from unittest.mock import MagicMock
from scraper import extract_next_links

class TestExtractNextLinks(unittest.TestCase):
    def test_extract_links(self):
        url = "http://example.com"
        resp = MagicMock()
        resp.status = 200
        resp.raw_response.content = """
        <html>
        <body>
        <a href="http://example.com/page1">Page 1</a>
        <a href="http://example.com/page2">Page 2</a>
        </body>
        </html>
        """.encode('utf-8')

        links = extract_next_links(url, resp)
        self.assertEqual(links, ["http://example.com/page1", "http://example.com/page2"])

if __name__ == '__main__':
    unittest.main()