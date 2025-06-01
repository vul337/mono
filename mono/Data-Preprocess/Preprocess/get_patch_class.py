import os.path
import re
import shutil, subprocess
from git import Repo


class Commit_Diff_Segment:
    def __init__(
        self,
        func_name,
        a_start,
        a_lines,
        b_start,
        b_lines,
        file_name,
        return_type,
        diff_lines,
        source_code,
        code_line_map_patch,
        code_line_map_unpatch,
    ):
        self._func_name = func_name
        self._a_start = a_start
        self._a_lines = a_lines
        self._b_start = b_start
        self._b_lines = b_lines
        self._file_name = file_name
        self._return_type = return_type
        self._diff_lines = diff_lines
        self._source_code = source_code
        self._code_line_map_patch = code_line_map_patch
        self._code_line_map_unpatch = code_line_map_unpatch

        self._add_lines = dict()
        self._delete_lines = dict()

    def __str__(self):
        return "\n".join(
            [
                self._file_name,
                self._a_start
                + ","
                + self._a_lines
                + " "
                + self._b_start
                + ","
                + self._b_lines,
                self._return_type + " " + self._func_name,
                self._source_code,
            ]
        )

    @property
    def source_code(self):
        return self._source_code


def is_source_code_file(filename):

    return (
        filename.endswith(".c")
        or filename.endswith(".cpp")
        or filename.endswith(".cxx")
    )


class patchCommit:
    def __init__(
        self, repository_path, oss_name, patch_commit, file, file_content=None
    ):
        self.repository_path = repository_path
        self._repository = Repo(self.repository_path)
        self.oss_name = oss_name
        self.patch_commit = patch_commit
        self.file = file
        self.file_content = file_content

    def retrieve_commit_content(self):
        commit_content = self._repository.git.show(f"{self.patch_commit}")

        diff_head_pattern = "diff --git a/(?P<filename>[\S]+)"
        match_ress = re.finditer(diff_head_pattern, commit_content)
        match_ress = list(match_ress)
        return_res = {}
        for idx in range(len(match_ress)):
            mr = match_ress[idx]
            filename = mr.groupdict()["filename"]
            if filename != self.file:
                continue
            if not is_source_code_file(filename):
                continue

            return_res[filename] = []
            patch_code_start = mr.span()[0]
            if idx == len(match_ress) - 1:
                patch_code_end = len(commit_content)
            else:
                patch_code_end = match_ress[idx + 1].span()[0]

            patch_code_content = commit_content[patch_code_start:patch_code_end]
            integer_pattern = "(?P<{}>[0-9]+)"
            function_header_pattern = "@@ -{},{} \+{},{} @@ (\S*?[\s]*)(?P<return_type>\S*?)[\s]*(?P<func_name>\S+)[\s]*\(.*?\)?.*?\n"
            function_header_pattern = function_header_pattern.format(
                integer_pattern.format("a_start"),
                integer_pattern.format("a_lines"),
                integer_pattern.format("b_start"),
                integer_pattern.format("b_lines"),
            )
            matched_functions = list(
                re.finditer(function_header_pattern, patch_code_content)
            )
            ll = len(matched_functions)
            code_line_map_patch = self.code_line_map(self.patch_commit)
            previous_hexsha = (
                self._repository.commit(self.patch_commit).parents[0].hexsha
            )
            code_line_map_unpatch = self.code_line_map(previous_hexsha)

            for idx in range(ll):
                func = matched_functions[idx]
                matched_dict = func.groupdict()
                matched_dict["file_name"] = filename
                a_start, a_lines, b_start, b_lines = (
                    matched_dict["a_start"],
                    matched_dict["a_lines"],
                    matched_dict["b_start"],
                    matched_dict["b_lines"],
                )

                diff_lines = (int(b_start) + int(b_lines)) - (
                    int(a_start) + int(a_lines)
                )
                matched_dict["diff_lines"] = diff_lines

                if idx == ll - 1:
                    code_end_pos = len(patch_code_content)
                else:
                    code_end_pos = matched_functions[idx + 1].span()[0]
                code_start_pos = func.span()[1]
                source_code = patch_code_content[code_start_pos:code_end_pos]
                matched_dict["source_code"] = source_code
                matched_dict["code_line_map_patch"] = code_line_map_patch
                matched_dict["code_line_map_unpatch"] = code_line_map_unpatch
                cds = Commit_Diff_Segment(**matched_dict)
                self.get_diff_lines(cds)
                return_res[filename].append(cds)
        return return_res, code_line_map_unpatch

    def get_diff_lines(self, cds: Commit_Diff_Segment):

        vul_index, patch_index = 0, 0
        for line in cds._source_code.split("\n"):
            if line.startswith("-"):
                cds._delete_lines[str(int(cds._a_start) + vul_index)] = line[1:].strip()
                vul_index += 1
            elif line.startswith("+"):
                cds._add_lines[str(int(cds._b_start) + patch_index)] = line[1:].strip()
                patch_index += 1
            else:
                vul_index += 1
                patch_index += 1

    def code_line_map(self, commit):
        code_line_map = dict()
        lineno = 0

        if self.file_content is not None:
            lines = self.file_content.splitlines()
            for line in lines:
                lineno += 1
                code_line_map[lineno] = line.strip()
            return code_line_map

        try:
            content = self._repository.git.show(f"{commit}:{self.file}")
            lines = content.splitlines()
            for line in lines:
                lineno += 1
                code_line_map[lineno] = line.strip()
        except Exception as e:
            print(f"Error reading file content: {str(e)}")
            return {}

        return code_line_map
