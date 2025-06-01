import requests
from bs4 import BeautifulSoup
import time
import os
import queue

from logging_helper import global_logger

def get_cve_description(cve_id, delay=1):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    }
    
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    
    try:
        time.sleep(delay)  
        response = requests.get(url, headers=headers)
        response.raise_for_status() 
        soup = BeautifulSoup(response.text, 'html.parser')
        description_tag = soup.find('p', {'data-testid': 'vuln-description'})
        
        if description_tag:
            return description_tag.text.strip()
        else:
            global_logger.warn(f"{cve_id} description not found.")
            return "no more info"
            
    except requests.exceptions.RequestException as e:
        global_logger.error(f"Request failed for {cve_id}: {e}")
        return "no more info"
    except Exception as e:
        global_logger.error(f"An error occurred for {cve_id}: {e}")
        return "no more info"