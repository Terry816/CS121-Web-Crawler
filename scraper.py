import re
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from collections import defaultdict
from urllib3.exceptions import NewConnectionError


url_visit_count = defaultdict(int)
allowed_domains = [
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu"
]
unique_urls = set()
url_word_count = defaultdict(int)

def scraper(url, resp):
    global url_word_count
    links = extract_next_links(url, resp)
    if resp.raw_response is not None:
        soup = BeautifulSoup(resp.raw_response.content.decode('utf-8', errors='ignore'), 'html.parser')
        # Remove HTML markup and count words
        words = re.findall(r'\b\w+\b', soup.get_text())
        url_word_count[url] = len(words)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.

    if resp.status != 200:
        print(resp.error)
        return []
    try:
        if not resp.raw_response:
            return []
        
        # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
        #         resp.raw_response.url: the url, again
        #         resp.raw_response.content: the content of the page!

        content = resp.raw_response.content.decode('utf-8', errors='ignore')
        soup = BeautifulSoup(content, 'html.parser')

        links = []
        for link in soup.find_all('a', href=True):
            links.append(link['href'])
        return links
    
    except NewConnectionError as e:
        print(f"Error connecting to {url}: {e}")
        return []

def is_valid(url):
    global url_visit_count
    try:
        parsed = urlparse(url)
        if not parsed.netloc or not parsed.path or parsed.scheme not in ['http', 'https']:
            return False  # Invalid URL
        
        # Check if the domain is in the list of allowed domains
        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
            return False

        # Check if URL has been visited more than 3 times in the last 10 seconds
        if url_visit_count[url] > 3 and time.time() - url_visit_count[url] < 10:
            return False
        
        # Increment the visit count for the URL
        url_visit_count[url] += 1

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
