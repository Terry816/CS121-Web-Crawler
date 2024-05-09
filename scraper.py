import re
from urllib.parse import urlparse, urljoin, urldefrag
from urllib import robotparser
from bs4 import BeautifulSoup
from collections import defaultdict, Counter
from urllib3.exceptions import NewConnectionError
from hashlib import blake2b
import nltk
from nltk.corpus import stopwords

#run the below code if you haven't downloaded the stopwords yet
#nltk.download('stopwords')

allowed_domains = [
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu"
]

THRESHOLD = 3
HASHBITS = 128
SIMHASH_THRESHOLD = .90
WORDS_THRESHOLD = 30
LOW_INFO_THRESHOLD = .2

# URL name of the page that has the largest number of words
maxpage = ""

# the largest number of words found in the largest page
maxwords = 0

# {parsed.netloc : robotparser}
robots_dict = {}

# set of visited pages
unique_urls = set()

#set of all the fingerprint bit values that we have already visited
fingerprints = set()

# {str: int} - dictionary of all the tokens from all the pages we have encountered
tokens = defaultdict(int)

# {url: int} keep tracks of the number of times we visited every page
url_visit_count = defaultdict(int)

# keeps track of the total number of pages that are valid
total_num_pages = 0

stop_words = set(stopwords.words('english'))
special_char = {"`", "~", "-", "_", "!", "?", ":", ";", ",", ".", "{", "}", "[", "]", "(", ")", "<", ">"}
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

def update_maxes(total_words: int, url):
    global maxwords, maxpage

    if total_words > maxwords:
        maxwords = total_words 
        maxpage = url


def is_low_info(unique_num: int, total: int) -> bool:
    #checks the ratio of unique words to the total amount of words.
    #returns True if the ratio is below the threshold which means content is low

    if total <= WORDS_THRESHOLD:
        return True
    
    ratio_unique = unique_num / total
    return ratio_unique < LOW_INFO_THRESHOLD

def simhash(token_counter):
    token_hash = {token: int(blake2b(token.encode(), digest_size=16).hexdigest(), 16) for token in token_counter}

    # Create a 128-dimensional vector V
    V = [0] * HASHBITS
    for token, count in token_counter.items():
        hash_value = token_hash[token]

        # Loop over each bit position
        for i in range(HASHBITS):
            bit = (hash_value >> i) & 1
            if (bit == 1):
                V[i] += count
            else:
                V[i] -= count

    # Generate the 128-bit fingerprint
    fingerprint = 0
    for i, value in enumerate(V):
        if value > 0:
            fingerprint |= (1 << i)
    
    return fingerprint

def similarity(hash1, hash2):
    # Compute the similarity - get a result that has 1s in positions where the bits are different between the two hashes, and 0s where the bits are the same.
    xor = hash1 ^ hash2

    # Count the number of 1 bits
    different_bits = bin(xor).count('1')

    # Return the ratio of different bits out of 128-bits
    return 1 - (different_bits / HASHBITS)

def tokenize(text, url):
    global stop_words, tokens, fingerprints

    #Accepts all words seperated by boundaries. "can't" -> "can" instead of "can't" -> "can", "t"

    token_list = re.findall(r'\b\w+\b', text.lower())
    token_counter = Counter(token_list)

    #check if the page has low information value
    total_words = len(token_list)
    unique_words = len(token_counter)
    if is_low_info(unique_words, total_words):
        return False

    #check if the content on this page is similar to the set of pages already
    fingerprint = simhash(token_counter)
    similar = any(similarity(fingerprint, f) >= SIMHASH_THRESHOLD for f in fingerprints)
    if similar:
        return False

    #if we do not find any similarity then we add it to the set
    fingerprints.add(fingerprint)

    #if it passes all the checks then we update our global tokens
    for t in token_list:
        if t not in stop_words and len(t) > 1:
            tokens[t] += 1
    
    #update the max page if this one is the largest
    update_maxes(total_words, url)

    return True

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
        print(f"Error code 200: {resp.error} from {resp.url}")
        return []
    elif resp.raw_response == None:
        print(f"None object extracted from this url: {resp.url}")
        return []
    elif resp.raw_response.content == None:
        print(f"Successful response 200 but content on the page is empty! URL: {resp.url}")
        return []

    # Redirection Handling (HTTP Status 300-310)
    if resp.status >= 300 and resp.status < 310:
        print(f"Redirection detected. Original URL: {url} \t Final URL: {resp.raw_response.url}")
        if is_valid(resp.raw_response.url):
            return [resp.raw_response.url]

    #second method to check for redirection
    if resp.raw_response.url.rstrip("/") != url:
        print(f"Second method detected redirection. original: {url}, redirected {resp.url}")
        if is_valid(resp.raw_response.url):
            return [resp.raw_response.url]


    #Crawl the final URL (resp.raw_response.url)
    try:
        soup = BeautifulSoup(resp.raw_response.content, "lxml")

        #tokenize the words on the page
        #Return true if we successfully did, if not we should return False and not crawl this page
        if not tokenize(soup.get_text(), url):
            return []
        
        total_num_pages+=1

        links = []
        for link in soup.find_all('a', href=True):
            relative = urldefrag(link.get("href"))[0]
            absolute = urljoin(resp.raw_response.url, relative)
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
        if not parsed.hostname or parsed.scheme not in ['http', 'https']: 
            return False
        
        # Check if the domain is in the list of allowed domains
        if not any(parsed.hostname.lower().endswith(domain) for domain in allowed_domains):
            return False

        
        #Checks for loop in path
        path_list = [p for p in parsed.path.split("/") if p]
        if path_list:
            count = Counter(path_list)
            if count.most_common(1)[0][1] > THRESHOLD:
                print(f"Path loop detected: {url}")
                return False


        # Increment the visit count for the URL
        skimmed = parsed.scheme + '://' + parsed.hostname + parsed.path
        url_visit_count[skimmed] += 1

        # Check if URL has been visited more than THRESHOLD times 
        if url_visit_count[skimmed] > THRESHOLD:
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

        file.write(f"Total number of unique pages: {total_num_pages}\n\n")

        file.write(f"Largest page: {maxpage}, word count: {maxwords}\n\n")

        word_tokens = {k: v for k, v in tokens.items() if not k.isdigit()}
        sorted_words = sorted(word_tokens.items(), key=lambda x: x[1], reverse=True)
        file.write("Top 60 words:\n")
        count = 1
        for token, freq in sorted_words[:60]:
            file.write(f"{count}. {token}: {freq}\n")
            count += 1

        subdomain_dict = count_subdomains(unique_urls)
        file.write("\nSubdomain in ics.uci.edu domain:\n")
        for subdomain, count in sorted(subdomain_dict.items(), key=lambda x: x[0].lower()):
            file.write(f"{subdomain}, {count}\n")
