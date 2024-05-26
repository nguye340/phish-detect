# phish-detect
Phish Detect is an automated playbook coded in Python to detect phishing emails. Source code below, feel free to modify and use it for your purpose:

```python
# Created by: Han Nguyen
# Last Modified: March 4th, 2024
# Purpose: Created a playbook to detect phishing email attempts based on their URL request event.
 
import phantom.rules as phantom
import json
import requests  # Note: Make sure requests is available in your Phantom environment

def on_start(container):
    # Attempt to collect URL artifacts
    urls = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL'])

    # Check if any URLs are found
    if not urls or not urls[0]:
        phantom.error('No URL artifacts found in the container')
        return  # Exit the function if no URLs are found
    
    # Loop through all URL artifacts
    for url_tuple in urls:
        url_to_check = url_tuple[0]  # Extract the URL from the tuple
        if url_to_check:
            check_url_with_ipqualityscore(container, url_to_check)
    

        
from urllib.parse import quote

def check_url_with_ipqualityscore(container, url_to_check):
    api_key = "JIImVabhVnNBNMgAcoXhXafbcD1kLOaM"
    encoded_url = quote(url_to_check, safe='')  # URL-encode the URL to be checked
    api_url = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"

    try:
        response = requests.get(api_url)
        response.raise_for_status()
        result = response.json()
        create_note(container, result, url_to_check)
    except requests.RequestException as e:
        error_message = f"API call to IPQualityScore failed: {str(e)}"
        phantom.error(error_message)
        create_note(container, {"error": error_message}, url_to_check, success=False)

        

def create_note(container, result, url, success=True):
    if success:
        if result.get('unsafe'):
            #check the value of unsafe parameter if it's true, if so the site is malicious
            message = f"IPQualityScore Check: The URL {url} is identified as malicious."
        else:
            message = f"IPQualityScore Check: The URL {url} is NOT identified as malicious."
    else:
        message = f"IPQualityScore Check failed to execute. Error: {result.get('error')}"

    phantom.debug(message)    
    phantom.add_note(container=container, note_type='general', title='IPQualityScore Check', content=message)


def on_finish(container, summary):
    phantom.debug('Playbook execution completed')
    
    return
```
