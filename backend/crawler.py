import asyncio
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

async def crawl_and_extract(base_url: str) -> list[dict]:
    """
    Crawls the given base_url, extracts forms and query parameters,
    and returns a list of dictionaries with method and params:
    [{"url": "...", "method": "GET|POST", "params": {"k": "v"}}]
    """
    try:
        response = await asyncio.to_thread(requests.get, base_url, timeout=10)
        response.raise_for_status()
    except Exception as e:
        print(f"Crawler failed to fetch {base_url}: {e}")
        return [{"url": base_url, "method": "GET", "params": {}}]

    soup = BeautifulSoup(response.text, 'html.parser')
    fuzzable_requests = []
    seen = set()

    # 1. Find all <a> tags with href containing query parameters
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(base_url, href)
        parsed_url = urlparse(full_url)
        
        if urlparse(base_url).netloc != parsed_url.netloc:
            continue
            
        params = parse_qs(parsed_url.query)
        if params:
            # Flatten lists to single strings
            flat_params = {k: v[0] for k, v in params.items()}
            clean_url = parsed_url._replace(query="").geturl()
            
            key = f"GET|{clean_url}|{sorted(flat_params.keys())}"
            if key not in seen:
                seen.add(key)
                fuzzable_requests.append({
                    "url": clean_url,
                    "method": "GET",
                    "params": flat_params
                })

    # 2. Find all <form> tags
    for form in soup.find_all('form'):
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        full_url = urljoin(base_url, action)
        parsed_url = urlparse(full_url)
        
        if urlparse(base_url).netloc != parsed_url.netloc:
            continue

        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data = {}
        for input_tag in inputs:
            name = input_tag.get('name')
            if not name:
                continue
            val = input_tag.get('value', 'test')
            form_data[name] = val
            
        if form_data:
            clean_url = parsed_url._replace(query="").geturl()
            key = f"{method}|{clean_url}|{sorted(form_data.keys())}"
            if key not in seen:
                seen.add(key)
                fuzzable_requests.append({
                    "url": clean_url,
                    "method": method,
                    "params": form_data
                })

    if not fuzzable_requests:
        fuzzable_requests.append({
            "url": base_url,
            "method": "GET",
            "params": {}
        })
        
    return fuzzable_requests
