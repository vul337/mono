from git import Repo
from typing import Dict, List, Tuple
from dataclasses import dataclass
from get_patch_class import patchCommit


@dataclass
class PatchInfo:
    file_path: str
    function_name: str
    deleted_lines: Dict[str, str]
    added_lines: Dict[str, str]

    
def analyze_patch(repo_path: str, commit_hash: str) -> List[PatchInfo]:
    repo = Repo(repo_path)
    commit = repo.commit(commit_hash)
    modified_files = []
    for diff in commit.parents[0].diff(commit):
        if diff.a_path:
            modified_files.append(diff.a_path)
    patches = []

    for file_path in modified_files:
        try:
            file_content = repo.git.show(f"{commit_hash}:{file_path}")
            patch = patchCommit(
                repository_path=repo_path,
                oss_name=repo_path.split("/")[-1],
                patch_commit=commit_hash,
                file=file_path,
                file_content=file_content,
            )

            commit_content, _ = patch.retrieve_commit_content()

            if file_path in commit_content:
                for segment in commit_content[file_path]:
                    patch_info = PatchInfo(
                        file_path=file_path,
                        function_name=segment._func_name,
                        deleted_lines=segment._delete_lines,
                        added_lines=segment._add_lines,
                    )
                    patches.append(patch_info)
        except Exception as e:
            print(f"Error processing file {file_path}: {str(e)}")
            continue

    return patches


def format_patch_summary(patches: List[PatchInfo]) -> str:
    summary = []

    for patch in patches:
        summary.append(f"\nFile: {patch.file_path}")
        summary.append(f"Modified function: {patch.function_name}")

        if patch.deleted_lines:
            summary.append("\nDeleted lines:")
            for line_num, code in patch.deleted_lines.items():
                summary.append(f"  Line {line_num}: {code}")

        if patch.added_lines:
            summary.append("\nAdded lines:")
            for line_num, code in patch.added_lines.items():
                summary.append(f"  Line {line_num}: {code}")

    return "\n".join(summary)
