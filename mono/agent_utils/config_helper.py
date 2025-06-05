from enum import Enum
from storage_helper import StorageLocation
import yaml

__all__ = ['config_file','crawling_language','CrawlingType']

SUPPORT_CRAWLING_LANGUAGE =  ['c_cpp' , 'java']
SUPPORT_CRAWLING_LANGUAGE
class CrawlingType(Enum):
    C_CPP = 'c_cpp'
    Java = 'java'

def read_config_file() -> dict:
    config_path = StorageLocation.config_path()
    github_token_path = StorageLocation.github_token_path()
    if not config_path.exists():
        raise Exception(f"config.yaml config file does not exist, create it in {config_path.absolute()}")

    if not github_token_path.exists():
        raise Exception(f"github_token.txt file does not exist, create it in {github_token_path.absolute()}")

    github_tokens = []
    github_username = []
    for token in github_token_path.open(mode='r').readlines():
        username, token = token.split('::')
        if token.startswith('ghp') or token.startswith('gho') or token.startswith('github'):
            github_username.append(username.strip())
            github_tokens.append(token.strip())
        else:
            raise Exception(f'Invalid github token {token},  start with "ghp" or "gho"')

    if len(github_tokens) < 1:
        raise Exception('At least 1 github tokens are required')

    config = yaml.safe_load(config_path.open(mode='r'))
    config['github_usernames'] = github_username
    config['github_tokens'] = github_tokens
    
    if 'crawling_language' not in config:
        raise RuntimeError(
            f"No programming language is specified for crawling, currently MegaVul support: {SUPPORT_CRAWLING_LANGUAGE}")
    elif config['crawling_language'] not in SUPPORT_CRAWLING_LANGUAGE:
        raise RuntimeError(
            f"Currently MegaVul only supports crawling the following programming languages: {SUPPORT_CRAWLING_LANGUAGE}")

    # config_file['repo_cache_dir'] = repo_cache_path

    return config

config_file = read_config_file()
crawling_language = CrawlingType(config_file['crawling_language'])
