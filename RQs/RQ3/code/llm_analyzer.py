from code_analyzer import CodeAnalyzer
from openai import OpenAI
from typing import List
import logging
import os
import sys
import time

from logging_helper import global_logger
logger = global_logger

os.environ['OPENAI_API_KEY'] = "aaaa"
os.environ['OPENAI_API_BASE'] = "http://127.0.0.1:8080/v1"
# os.environ['OPENAI_API_KEY'] = "aaaa"
# os.environ['OPENAI_API_BASE'] = "http://

model_aliases = {
    # Qwen Series (Non-reasoning Instruct)
    'qn-7b': 'Qwen/Qwen2.5-7B-Instruct',
    'qn-14b': 'Qwen/Qwen2.5-14B-Instruct',
    'qn-32b': 'Qwen/Qwen2.5-32B-Instruct',
    'qn-72b': 'Qwen/Qwen2.5-72B-Instruct',
    'qn3-32b': 'Qwen/Qwen3-32B',
    'qn3-32b-0': 'Qwen/Qwen3-32B',
    "qn3-235b": "Qwen/Qwen3-235B-A22B",

    # DeepSeek R1 Distill (Reasoning)
    # Note: Based on comments, these are Distill versions of DeepSeek R1.
    'r1-qn-7b': 'Pro/deepseek-ai/DeepSeek-R1-Distill-Qwen-7B',
    'r1-qn-14b': 'deepseek-ai/DeepSeek-R1-Distill-Qwen-14B',
    'r1-qn-32b': 'deepseek-ai/DeepSeek-R1-Distill-Qwen-32B', 
    'r1-lm-8b': 'deepseek-ai/DeepSeek-R1-Distill-Llama-8B',
    'r1-lm-70b': 'deepseek-ai/DeepSeek-R1-Distill-Llama-70B',

    # Llama Series (Non-reasoning Instruct)
    'lm-8b': 'meta-llama/Meta-Llama-3.1-8B-Instruct',
    'lm-70b': 'meta-llama/Meta-Llama-3.1-70B-Instruct',
    'lm-405b': 'meta-llama/Meta-Llama-3.1-405B-Instruct', 

    # DeepSeek Native Series
    'ds-v3': 'Pro/deepseek-ai/DeepSeek-V3', # DeepSeek-V3
    'ds-r1': 'Pro/deepseek-ai/DeepSeek-R1', # DeepSeek-R1

    # OpenAI Series
    'o3-mini': 'o3-mini',
    # '4o': 'gpt-4o',
    '4o': 'gpt-4o-2024-08-06',
    '4': 'gpt-4',
}


model_aliases = {
    # Qwen Series (Non-reasoning Instruct)
    'qn-7b': 'Qwen/Qwen2.5-7B-Instruct',
    'qn-14b': 'Qwen/Qwen2.5-14B-Instruct',
    'qn-32b': 'Qwen/Qwen2.5-32B-Instruct',
    'qn3-32b': 'Qwen/Qwen3-32B',
    'qn3-32b-0': 'Qwen/Qwen3-32B', # no reasoning

    # DeepSeek R1 Distill (Reasoning)
    # Note: Based on comments, these are Distill versions of DeepSeek R1.
    'r1-qn-7b': 'Pro/deepseek-ai/DeepSeek-R1-Distill-Qwen-7B',
    'r1-qn-14b': 'deepseek-ai/DeepSeek-R1-Distill-Qwen-14B',
    'r1-qn-32b': 'deepseek-ai/DeepSeek-R1-Distill-Qwen-32B', 

    # Llama Series (Non-reasoning Instruct)
    'lm-8b': 'meta-llama/Meta-Llama-3.1-8B-Instruct',
    'lm-70b': 'meta-llama/Meta-Llama-3.1-70B-Instruct',
   
    # DeepSeek Native Series
    'ds-v3': 'Pro/deepseek-ai/DeepSeek-V3', # DeepSeek-V3
    'ds-r1': 'Pro/deepseek-ai/DeepSeek-R1', # DeepSeek-R1

    # OpenAI Series
    '4': 'gpt-4',
}

def get_analyzer(model_alias):
    full_model_id = model_aliases.get(model_alias)

    if full_model_id is None:
        available_aliases = ', '.join(model_aliases.keys())
        raise ValueError(f"Unknown analyzer model alias: '{model_alias}'. Available aliases: {available_aliases}")

    api_key = os.environ.get('OPENAI_API_KEY', 'dummy_key') 
    api_base = os.environ.get('OPENAI_API_BASE', 'http://localhost:8080/v1') 
    logger.info(f"Using API base: {api_base}")
    logger.info(f"Using model ID: {full_model_id}")

    try:
        analyzer = OpenAIAnalyzer(api_key=api_key, base_url=api_base, model=full_model_id)
        # analyzer = OpenAIStreamAnalyzer(api_key=api_key, base_url=api_base, model=full_model_id)
        # print(f"Initialized new analyzer for '{model_alias}' using model ID '{full_model_id}'\nuse API base: {api_base}")
    except Exception as e:
         raise RuntimeError(f"Failed to initialize analyzer for model '{full_model_id}' (alias '{model_alias}'): {e}") from e

    return analyzer



class OpenAIAnalyzer(CodeAnalyzer):
    def __init__(
        self,
        api_key=os.environ['OPENAI_API_KEY'],
        model: str = "gpt-4o-2024-11-20",
        base_url=os.environ['OPENAI_API_BASE'],
        max_tokens=24576,
        system_prompt="",
        temperature=0.6,
        retries: int = 2,  
        backoff_factor: float = 0.5, 
    ):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.system_prompt = system_prompt
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.topp = 0.95
        self.retries = retries
        self.backoff_factor = backoff_factor

    def generate(
        self,
        prompt: str,
        system_prompt: str = "You are a vulnerability detection expert specializing in identifying specific types of vulnerabilities, particularly related to the Common Weakness Enumeration (CWE) standards.",
    ) -> str:
        prompt = prompt+"/no_think"
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        for attempt in range(self.retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=self.temperature,
                    # max_completion_tokens=self.max_tokens,
                    top_p=self.topp,
                )

                # print(f"API call successful. Finish reason: {finish_reason}")

                if (
                    "reasoning_content" in response.choices[0].message.model_extra
                    and response.choices[0].message.model_extra["reasoning_content"] is not None
                    and response.choices[0].message.model_extra["reasoning_content"] != ""
                ):
                    return (
                        response.choices[0].message.model_extra["reasoning_content"]
                        + response.choices[0].message.content
                    )
                return response.choices[0].message.content

            except Exception as e:
                if attempt < self.retries - 1:
                    sleep_time = self.backoff_factor * (2 ** attempt)
                    print(f"Retrying in {sleep_time:.2f} seconds...")
                    time.sleep(sleep_time)
                else:
                    logger.error(f"All {self.retries} attempts failed. Could not generate response.")
                    print(f"All {self.retries} attempts failed. Could not generate response.")
                    raise

        return ""

class OpenAIStreamAnalyzer(CodeAnalyzer):
    def __init__(
        self,
        api_key=os.environ.get('OPENAI_API_KEY'), 
        model: str = "gpt-4o-2024-11-20",
        base_url=os.environ.get('OPENAI_API_BASE'), 
        max_tokens=4096,
        system_prompt="",
        temperature=0.6,
        retries: int = 2,
        backoff_factor: float = 0.5,
    ):
       
        if not base_url:
            raise ValueError("OPENAI_API_BASE environment variable or base_url argument is required.")

        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.system_prompt = system_prompt
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.topp = 0.95
        self.retries = retries
        self.backoff_factor = backoff_factor

    def generate(
        self,
        prompt: str,
        system_prompt: str = "You are a vulnerability detection expert specializing in identifying specific types of vulnerabilities, particularly related to the Common Weakness Enumeration (CWE) standards.",
    ) -> str:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        
        full_content = ""
        full_reasoning_content = ""
        finish_reason = None

        for attempt in range(self.retries):
            try:
                response_stream = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens, 
                    top_p=self.topp,
                    stream=True, 
                )

             
                for chunk in response_stream:
                    if chunk.choices and len(chunk.choices) > 0:
                        delta = chunk.choices[0].delta
                        
                        
                        if delta.content:
                            full_content += delta.content
                        
                        if "reasoning_content" in delta.model_extra and delta.model_extra["reasoning_content"] is not None:
                            full_reasoning_content += delta.model_extra["reasoning_content"]
                        
                        if chunk.choices[0].finish_reason:
                            finish_reason = chunk.choices[0].finish_reason
                logger.info(f"API call successful. Finish reason: {finish_reason}")
                # print(f"API call successful. Finish reason: {finish_reason}")
                if full_reasoning_content:
                    return full_reasoning_content + full_content
                
                return full_content

            except Exception as e:
                if attempt < self.retries - 1:
                    sleep_time = self.backoff_factor * (2 ** attempt)
                    print(f"Retrying in {sleep_time:.2f} seconds due to error: {e}")
                    time.sleep(sleep_time)
                else:
                    logger.error(f"All {self.retries} attempts failed. Could not generate response. Error: {e}")
                    print(f"All {self.retries} attempts failed. Could not generate response. Error: {e}")
                    raise

        return ""  
    

class O3Analyzer(CodeAnalyzer):
    def __init__(
        self,
        api_key: str,
        model: str = "o3-mini",
        base_url="",
        max_tokens=int(65536),
        system_prompt="",
        temperature=0.6,
        mode="medium",
    ):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
        self.system_prompt = system_prompt
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.mode = mode
        self.reasoning_tokens = 0

    def generate(
        self,
        prompt: str,
        system_prompt: str = "You are a vulnerability detection expert specializing in identifying specific types of vulnerabilities, particularly related to the Common Weakness Enumeration (CWE) standards.",
    ) -> str:

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_completion_tokens=self.max_tokens,
            reasoning_effort=self.mode,
        )
        reasoning_tokens = response.usage.completion_tokens
        self.reasoning_tokens = reasoning_tokens
        if (
            "reasoning_content" in response.choices[0].message.model_extra
            and response.choices[0].message.model_extra["reasoning_content"] != None
            and response.choices[0].message.model_extra["reasoning_content"] != ""
        ):
            return (
                response.choices[0].message.model_extra["reasoning_content"]
                + response.choices[0].message.content
            )
        return response.choices[0].message.content

    def get_reasoning_tokens(self):
        return self.reasoning_tokens



# class DeepSeekR1Analyzer(CodeAnalyzer):

if __name__ == "__main__":
    # Example usage
    model_alias = 'lm-8b'  # Change this to the desired model alias
    analyzer = get_analyzer(model_alias)
    prompt = "Analyze the following code for vulnerabilities: ..."
    response = analyzer.generate(prompt)
    print(response)