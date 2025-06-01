import os
from pathlib import Path
from typing import Optional, Dict, Any, Union, List
import requests
import time
import json
import ast
import shutil
import glob
import hashlib
import subprocess

class JoernService:
    def __init__(
        self,
        base_url: str = "http://localhost:2000",
        out_workspace: str = "./app/workspace",
        out_cache: str = "./app/cache",   
    ):
        self.base_url = base_url
        self.workspace = "/app/workspace"
        self.app_root = "/app" 
        self.cache_root = "/app/cache"

        self.out_cache = out_cache
        self.out_workspace = out_workspace
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
    
    
    def _resolve_paths(self, project_path: str) -> Dict[str, Path]:
        if "/app" not in project_path:
            print("Project path must have /app path")
            return []
        
        project_path = project_path.split("/app")[-1]
        project_path = "/app" + project_path
        print(project_path)
        container = project_path
        cache_dir = Path(self.cache_root) / hashlib.md5(project_path.encode()).hexdigest()
        return {
            "container": container,
            "cache_dir": cache_dir,
            # "in_workspace": f"{self.workspace}/{cache_dir.name}",
            "out_workspace": f"{self.out_workspace}/{cache_dir.name}",
        }

    def _query(self, query: str, retries: int = 3) -> str:
        url = f"{self.base_url}/query"
        for _ in range(retries):
            try:
                resp = self.session.post(url, json={"query": query})
                resp.raise_for_status()
                result = resp.json()
                if not result['success']:
                    raise RuntimeError(f"Query failed: {result.get('error')}")
                uuid = result['uuid']
                result_url = f"{self.base_url}/result/{uuid}"
                start = time.time()
                while time.time() - start < 200:
                    resp = self.session.get(result_url)
                    resp.raise_for_status()
                    result = resp.json()
                    
                    if result['success']:
                        return result['stdout']
                    
                    time.sleep(0.1)
                return "Query timed out"
            
            except requests.exceptions.ConnectionError:
                time.sleep(1)
                continue
        
        raise ConnectionError(f"Failed after {retries} retries")

    def _parse_response(self, res: str) -> Any:
        # print(res)
        res = res.strip()
        ret_pos = res.rfind('\n')
        if ret_pos >= 0:
            res = res[ret_pos + 1:]
        begin_label = "= "
        begin_pos = res.find(begin_label) + len(begin_label)
        res = res[begin_pos:].strip()
        if res.startswith('"""'):
            res = res.strip('"')
        elif res.startswith('/'):
            return res
        elif res.startswith('List('):
            res = res[5:-1]
            res = res.split(", ")
        else:
            try:
                res = ast.literal_eval(res)
            except Exception as e:
                print(e)
                res = "error"
        return res

    
    def query_json(self, query: str) -> Any:
        if not query.strip().endswith('.toJson'):
            query += '.toJson'
        # print(query)
        res = self._query(query)
        # print(res)
        stripped_json = self._parse_response(res)
        try:
            return json.loads(stripped_json)
        except json.JSONDecodeError as e:
            # raise Exception(stripped_json)
            # print(f"Error decoding JSON: {stripped_json}")
            return None


    def run_script(self, script_path: str) -> Any:
        # container_script = self.app_root + "/" + script_path.lstrip('/')
        container_script = script_path
        print(f"Running script: {container_script}")
        response = self._query(f'//> using file {container_script}')
        print(response)
        return self._parse_response(response)

    def init_project(self, project_path: str) -> str:
        paths = self._resolve_paths(project_path)
        if not paths:
            return ""

        out_cache_cpg = f"{self.out_cache}{paths['cache_dir'].name}/cpg.bin" # out
        cache_path = paths['cache_dir'] / "cpg.bin" # container
        out_workspace_path = paths['out_workspace']
        if os.path.exists(out_workspace_path):
            print("Workspace already exists, importing it...")
            res = self._query(f'open("{paths["cache_dir"].name}")')
            if "Graph[0 nodes]" in res:
                res = self._query(f'importCpg("/app/workspace/{paths["cache_dir"].name}/cpg.bin")')
                if "Graph[0 nodes]" in res:
                    return "0 nodes"
            print(res)
        elif os.path.exists(out_cache_cpg):
            print("CPG already exists, importing it...")
            res = self._query(f'importCpg("{cache_path}"), projectName="{paths["cache_dir"].name}")')
            print(res)
        else:
            print("CPG or Workspace not exists, importing it...")
            try:
                res = self._query(f'importCode("{paths["container"]}", projectName="{paths["cache_dir"].name}")')
                print(res)
                if res:
                    # if os.path.exists(self.out_cache):
                    #     shutil.rmtree(self.out_cache)
                    out_cache_dir = self.out_cache + '/' + paths['cache_dir'].name
                    shutil.copytree(out_workspace_path, out_cache_dir, dirs_exist_ok=True)
                    # os.system(f"rsync -a .{workspace_path} {self.out_cache}")
                    # print(res)
                else:
                    print("Error: CPG import failed.")
                    return "error"
            except Exception as e:
                print(f"Error: {e}")
                return "error"
        return paths["cache_dir"].name
    
    def import_cpg(self, project_path: str) -> str: 
        # cpg is at project_path/cpg.bin
        out_cpg = f"{project_path}/cpg.bin"
        if not os.path.exists(out_cpg):
            print(f"Error: CPG not found at {out_cpg}")
            return "error"

        paths = self._resolve_paths(project_path)
        if not paths:
            return ""

        inner_cpg = f"{paths['container']}/cpg.bin"
        res = self._query(f'importCpg("{inner_cpg}", projectName="{paths["cache_dir"].name}")')
        print(res)

        return paths["cache_dir"].name


    # without jq._query
    def static_cpg_gen( 
        self,
        project_path: str,
        output_dir: Optional[str] = None,
        exclude_regex: Optional[str] = None
    ) -> str:
        project_dir = Path(project_path)
        if not project_dir.exists() or not project_dir.is_dir():
            raise ValueError(f"Invalid project_path: {project_path}")

        cpg_root = Path(output_dir) if output_dir else project_dir / "Joern_files"
        cpg_root.mkdir(parents=True, exist_ok=True)

        cpg_file = cpg_root / "cpg.bin"
        if cpg_file.exists() and cpg_file.is_file():
            print(f"CPG already exists at {cpg_file}.")
            return str(cpg_root)

        cmd = [
            "joern-parse",
            str(project_dir),
            "-o", str(cpg_file)
        ]
        if exclude_regex:
            cmd.extend(["--exclude-regex", exclude_regex])
        print(f"Generating CPG for {project_path} at {cpg_file}...")
        try:
            subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"CPG generation failed: {e}")
        print(f"CPG generated at: {cpg_file}")
        return str(cpg_root)
        
    
    def close_project(self, project_name: str):
        self.session.close()
        res = self._query(f"""close("{project_name}")""")
        # rm -rf ./app/workspace/cpg.bin1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
        cpg_bin = f".{self.workspace}/cpg.bin*"
        cpg_bin = glob.glob(cpg_bin)
        for files in cpg_bin:
            try:
                shutil.rmtree(files)
            except OSError as e:
                print(e)
        print(res)


if __name__ == '__main__':
    jq = JoernService()
