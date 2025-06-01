from abc import ABC, abstractmethod
from typing import List
from dataclass import VulnPairWithContext
from prompt import get_zero_shot_cot_prompt_with_more_context

import sys
sys.path.append("/agent_utils")

from logging_helper import global_logger
logger = global_logger


class CodeAnalyzer(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        pass
    
    def zeroShotCoTAnalyze(self, pair: VulnPairWithContext, is_vuln: bool, context_on: bool=True):
        prompt = get_zero_shot_cot_prompt_with_more_context(pair, is_vuln, context_on)
        response = self.generate(prompt)
        # logger.info(f"response: {response}")
        # input()
        
        if "HAS_VUL" in response or "has_vul" in response or "YES_VUL" in response or "HAS\_VUL" in response or "HAS\\_VUL" in response:
            return 1, response
        elif "NO_VUL" in response or "no_vul" in response or "NO\\_VUL" in response or "NO\_VUL" in response:
            return 0, response
        return -1, response

