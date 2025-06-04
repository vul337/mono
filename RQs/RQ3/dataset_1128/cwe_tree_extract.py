from bs4 import BeautifulSoup

TARGET_CWE_NUMBERS = ['693', '284', '664', '682', '703', '707', '691', '710']
# https://cwe.mitre.org/data/definitions/1000.html
def load_html(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def extract_cwe_tree(html_content, targets):
    soup = BeautifulSoup(html_content, 'html.parser')
    result = {num: [] for num in targets}
    for num in targets:
        prefix = f"1000{num}"
        for div in soup.find_all("div"):
            div_id = div.get("id", "")
            if div_id.startswith(prefix):
                tree_code = div_id[4:]
                result[num].append({'tree_code': tree_code})
    return result

def find_parent_code(code, all_codes, current_level_codes):
    if len(code) == 0:
        
        return None
    for i in range(len(code) - 1, 0, -1):
        prefix = code[:i]
        if prefix in current_level_codes:
            return prefix
        if prefix in all_codes:
            return prefix
    return None

def build_tree(tree_codes, root_code):
    tree = {}
    for code in tree_codes:
        if code == root_code:
            continue
        parent = None
        for i in range(len(code)-1, 0, -1):
            potential_parent = code[:i]
            if potential_parent in tree_codes:
                parent = potential_parent
                break
        if parent is None:
            parent = root_code
        if parent not in tree:
            tree[parent] = []
        tree[parent].append(code)
    return tree

def write_tree(f, tree, code, parent_code='', level=0, visited=None):
    if visited is None:
        visited = set()
    if code in visited:
        return
    visited.add(code)
    indent = '-' * level
    if level == 0:
        display_code = code
    else:
        display_code = code[len(parent_code):]
    f.write(f"{indent}{display_code}\n")
    if code in tree:
        for child in sorted(tree[code]):
            write_tree(f, tree, child, code, level + 1, visited)

def save_tree_to_txt(tree_codes, root_code, filename):
    tree = build_tree(tree_codes, root_code)
    with open(filename, 'w', encoding='utf-8') as f:
        write_tree(f, tree, root_code)

if __name__ == '__main__':
    html_file = r'\WE - CWE-1000_ Research Concepts (4.17).html'
    html = load_html(html_file)
    tree_by_targets = extract_cwe_tree(html, TARGET_CWE_NUMBERS)
    for num in TARGET_CWE_NUMBERS:
        tree_codes = [item['tree_code'] for item in tree_by_targets[num]]
        save_tree_to_txt(tree_codes, root_code=num, filename=f'cwe_{num}_tree.txt')
