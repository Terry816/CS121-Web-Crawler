import re
import time
from urllib.parse import urlparse, urlunparse, urljoin
from urllib import robotparser
from bs4 import BeautifulSoup
from collections import defaultdict, Counter
from urllib3.exceptions import NewConnectionError

import nltk
from nltk.tokenize import RegexpTokenizer
from nltk.corpus import stopwords

#run the below code if you haven't downloaded the stopwords yet
#nltk.download('stopwords')

allowed_domains = [
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu"
]

THRESHOLD = 5

# URL name of the page that has the largest number of words
maxpage = ""

# the largest number of words found in the largest page
maxwords = 0

# {parsed.netloc : robotparser}
robots_dict = {}

# set of visited pages
unique_urls = set()

# {str: int} - dictionary of all the tokens from all the pages we have encountered
tokens = defaultdict(int)

# {url: int} keep tracks of the number of times we visited every page
url_visit_count = defaultdict(int)

# keeps track of the total number of pages that are valid
total_num_pages = 0

stop_words = set(stopwords.words('english'))
special_char = {"-", "!", "?", ":", ";", ",", ".", "{", "}", "[", "]", "(", ")", "<", ">"}
stop_words.update(special_char)


def check_robots(parsed):
    domain = parsed.netloc
    if domain not in robots_dict:
        base = parsed.scheme + "://" + domain + "/robots.txt"
        robotparse = robotparser.RobotFileParser(base)
        try:
            robotparse.read()
            robots_dict[domain] = robotparse
            return robotparse
        except:
            robots_dict[domain] = None
            return None
    else:
        return robots_dict[domain]

def strip_fragment_from_url(url):
    parsed_url = urlparse(url)
    # Return the URL without the fragment
    return urlunparse(parsed_url._replace(fragment=''))


def update_maxes(total_words: int, url):
    global maxwords, maxpage

    if total_words > maxwords:
        maxwords = total_words 
        maxpage = url


def is_low_info(tokens: int, total: int) -> bool:
    #checks the ratio of unique words to the total amount of words. 
    #Return True if no words or if the ratio is less than 0.2 then there are a lot of duplicate words
    if total > 0:
        ratio_unique = tokens / total
        return ratio_unique < .2
    else: 
        #Return True is there are no words
        return True


def tokenize(text, url):
    global stop_words, tokens

    #Accepts all words seperated by boundaries. "can't" -> "can" instead of "can't" -> "can", "t"
    tokenizer = RegexpTokenizer(r'\b\w+\b')
    token_list = tokenizer.tokenize(text.lower())

    total_words = len(token_list)

    #check if the page has low information value
    if is_low_info(len(set(token_list)), total_words):
        return

    #update our global tokens
    for t in token_list:
        if t not in stop_words:
            tokens[t] += 1

    update_maxes(total_words, url)

    return


def scraper(url, resp):
    global unique_urls

    unique_urls.add(url)
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]


def extract_next_links(url, resp):
    
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    # resp.raw_response.url: the url, again
    # resp.raw_response.content: the content of the page!

    global total_num_pages

    #Error Handling (HTTP Status - 200)
    if resp.status != 200:
        print(f"Error code 200: {resp.error}")
        return []
    elif resp.raw_response.content == None:
        print(f"Successful response 200 but content on the page is empty! URL: {resp.url}")
        return []
    elif resp.raw_response == None:
        print(f"None object extracted from this url: {resp.url}")
        return []

    #Redirection Handling (HTTP Status 300-309)
    if resp.status > 300 and resp.status < 310:
        print(f"Redirection detected. Original url : {resp.url} \t Final url: {resp.raw_response.url}")
        if is_valid(resp.raw_response.url):
            return [resp.raw_response.url]

    #Checking redirection with comparing original URL with the final URL in case of invalid HTTP status response (edge cases)
    elif url != resp.raw_response.url.rstrip("/"): 
        print(f"Original URL and Final URL are not equivalent, redirection detected")
        return [resp.raw_response.url]


    #Crawl the final URL (resp.raw_response.url)
    try:
        content = resp.raw_response.content.decode('utf-8', errors='ignore')
        soup = BeautifulSoup(content, 'lxml')
        total_num_pages+=1


        #tokenize the words on the page
        tokenize(soup.get_text(), resp.raw_response.url) # returns a list of tokens empty if it has low info

        links = []
        for link in soup.find_all('a', href=True):
            relative = strip_fragment_from_url(link['href']) #Strip the fragement
            absolute = urljoin(resp.raw_response.url, relative) #Transform to absolute path
            links.append(absolute)

        return links
    
    except NewConnectionError as e: #catches server down, network/connectivity issues
        print(f"Error connecting to {url}. Message: {e}")
        return []

def is_valid(url):
    global url_visit_count
    try:
        parsed = urlparse(url)

        # Check if the url is not None and URL scheme is http or https 
        if not parsed.netloc or parsed.scheme not in ['http', 'https']: 
            return False
        
        # Check if the domain is in the list of allowed domains
        if not any(parsed.netloc.endswith(domain) for domain in allowed_domains):
            return False


        # Increment the visit count for the URL
        url_visit_count[url] += 1

        # Check if URL has been visited more than THRESHOLD times in the last 15 seconds (trap)
        if url_visit_count[url] > THRESHOLD and time.time() - url_visit_count[url] < 15:
            return False

        # Check if URL has been stuck in an infinite loop of repeating directories/path (trap)
        path_list = parsed.path.split("/")
        count = Counter(path_list)
        if count.most_common(1)[0][1] > THRESHOLD:
            return False

        
        # Check if url can be crawled in the robots.txt permissions
        robotparse = check_robots(parsed)
        if robotparse and not robotparse.can_fetch("*", url):
            return False
        

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

def count_subdomains(uniques: set):
    subdomain_dict = defaultdict(int)
    for i in uniques:
        parsed = urlparse(i)
        if parsed.netloc != "www.ics.uci.edu" and parsed.netloc.endswith(".ics.uci.edu"):
            subdomain_dict[parsed.netloc] += 1
    return subdomain_dict

def report_to_file():
    with open('result.txt', 'w') as file:

        file.write(f"Total number of unique pages: {total_num_pages}\n")

        file.write(f"Largest page: {maxpage}, word count: {maxwords}\n")

        word_tokens = {k: v for k, v in tokens.items() if not k.isdigit()}
        sorted_words = sorted(word_tokens.items(), key=lambda x: x[1], reverse=True)
        file.write("Top 50 words:\n")
        for token, freq in sorted_words[:50]:
            file.write(f"{token}: {freq}\n")

        subdomain_dict = count_subdomains(unique_urls)
        file.write("Subdomain in ics.uci.edu domain:\n")
        for subdomain, count in sorted(subdomain_dict.items(), key=lambda x: x[0]):
            file.write(f"{subdomain}, {count}\n")
