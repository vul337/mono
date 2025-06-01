
import os
import re
import json
import sqlite3
import shutil
import sys
from collections import defaultdict


from logging_helper import global_logger

CVE_PATTERN = re.compile(
    r'^(CVE-\d{4}-\d+)(?:_(\d+))?(?:_part(\d+))?\.json$'
)

# LANGUAGE = 'c_cpp'
LANGUAGE = 'java'

def organize_cve_files(source_root, target_root):
    """Main function to organize CVE files"""
    global_logger.info(f"Starting CVE organization. Source: {source_root}, Target: {target_root}")
    

    cve_db = defaultdict(lambda: {
        "dir": "",
        "all": set(),
        "sec_vul": set(),
        "non_sec_vul": defaultdict(set),
        "types": defaultdict(lambda: defaultdict(set))
    })

    # Phase 1: Collect files
    global_logger.info("Phase 1: Collecting files...")
    for root, _, files in os.walk(source_root):
        for filename in files:
            if not filename.endswith('.json'):
                continue
                
            process_file(root, filename, source_root, cve_db)

    # Phase 2: Process and organize files
    global_logger.info("\nPhase 2: Processing files...")
    for cve_id, data in cve_db.items():
        process_cve(cve_id, data, source_root, target_root)

    # Phase 3: Create database
    global_logger.info("\nPhase 3: Creating database...")
    create_database(cve_db, target_root)

def process_file(root, filename, source_root, cve_db):
    """Process individual file"""
    match = CVE_PATTERN.match(filename)
    if not match:
        global_logger.warning(f"Skipping invalid filename: {filename}")
        return

    base_cve, mid_num, part_num = match.groups()
    rel_path = os.path.relpath(root, source_root).split(os.sep)
    
    # Classify file type
    file_type = classify_file(rel_path, filename)
    
    # Update database
    entry = cve_db[base_cve]
    entry["dir"] = base_cve
    entry["all"].add(filename)
    
    if file_type["category"] == "sec_vul":
        entry["sec_vul"].add(filename)
    elif file_type["category"] == "non_sec_vul":
        entry["non_sec_vul"][file_type["subtype"]].add(filename)
        entry["types"][file_type["subtype"]][file_type["location"]].add(filename)

def classify_file(path_parts, filename):
    """Classify file into proper categories"""
    classification = {
        "category": "other",
        "subtype": None,
        "location": "main_dir"
    }
    
    if path_parts[0] == 'sec_vul':
        classification["category"] = "sec_vul"
        classification["location"] = "no_more_info" if 'no_more_info' in path_parts else "main_dir"
    elif path_parts[0] == 'non_sec_vul' and len(path_parts) >= 2:
        classification["category"] = "non_sec_vul"
        classification["subtype"] = path_parts[1]
        classification["location"] = "no_more_info" if 'no_more_info' in path_parts else "main_dir"
    
    if '_broken' in filename:
        classification["category"] = "broken"
        
    return classification

def custom_sort_key(filename):
    """Custom sorting key for CVE files"""
    match = CVE_PATTERN.match(filename)
    if not match:
        return (999, 999, 999)  # Push invalid files to end
    
    base, mid, part = match.groups()
    mid_num = int(mid) if mid else -1  # -1 for files without middle number
    part_num = int(part) if part else 0
    
    # Sorting priority: main files -> numbered files
    return (mid_num, part_num)

def process_cve(cve_id, data, source_root, target_root):
    """Process individual CVE"""
    global_logger.info(f"Processing {cve_id}")
    
    # Create directory structure
    cve_dir = os.path.join(target_root, cve_id)
    os.makedirs(cve_dir, exist_ok=True)
    
    # Initialize data structures
    stats = init_stats()
    stats["cve_id"] = cve_id
    raw_data = {}
    
    # Process sorted files
    for filename in sorted(data["all"], key=custom_sort_key):
        src_path = find_original_path(source_root, filename)
        if not src_path:
            continue
            
        # Copy file to new structure
        dest_path = build_dest_path(src_path, source_root, cve_dir)
        safe_file_copy(src_path, dest_path)
        
        # Update statistics
        update_stats(stats, src_path, filename)
        
        # Merge data
        merge_json_data(src_path, raw_data)

    generate_summary(cve_dir, cve_id, stats, raw_data)

def init_stats():
    """Initialize statistics structure"""
    return {
        "cve_id": "",
        "language": LANGUAGE,
        "sec_vul": {
            "num": 0,
            "no_more_info": [],
            "main_dir": []
        },
        "non_sec_vul": {
            "num": 0,
            "types": defaultdict(lambda: {
                "num": 0,
                "no_more_info": [],
                "main_dir": []
            })
        }
    }

def update_stats(stats, src_path, filename):
    """Update statistics with correct categorization"""
    path_parts = src_path.split(os.sep)
    
    if 'sec_vul' in path_parts:
        target = stats["sec_vul"]
        key = "no_more_info" if 'no_more_info' in path_parts else "main_dir"
        target[key].append(filename)
        target["num"] += 1
    elif 'non_sec_vul' in path_parts:
        try:
            subtype = path_parts[path_parts.index('non_sec_vul')+1]
            target = stats["non_sec_vul"]["types"][subtype]
            key = "no_more_info" if 'no_more_info' in path_parts else "main_dir"
            target[key].append(filename)
            target["num"] += 1
            stats["non_sec_vul"]["num"] += 1
        except (ValueError, IndexError):
            global_logger.error(f"Invalid path structure: {src_path}")

def build_dest_path(src_path, source_root, cve_dir):
    """Build destination path from source structure"""
    rel_path = os.path.relpath(src_path, source_root)
    parts = rel_path.split(os.sep)
    
    if parts[0] == 'sec_vul':
        if 'no_more_info' in parts:
            return os.path.join(cve_dir, 'sec_vul', 'no_more_info', os.path.basename(src_path))
        return os.path.join(cve_dir, 'sec_vul', os.path.basename(src_path))
    
    if parts[0] == 'non_sec_vul' and len(parts) >= 2:
        subtype = parts[1]
        if 'no_more_info' in parts:
            return os.path.join(cve_dir, 'non_sec_vul', subtype, 'no_more_info', os.path.basename(src_path))
        return os.path.join(cve_dir, 'non_sec_vul', subtype, os.path.basename(src_path))
    
    return os.path.join(cve_dir, 'other', os.path.basename(src_path))

def safe_file_copy(src, dest):
    """Copy files with error handling"""
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
    except Exception as e:
        global_logger.error(f"Copy failed: {src} -> {dest} ({str(e)})")

def merge_json_data(src_path, raw_data):
    """Merge JSON content from source file"""
    try:
        with open(src_path) as f:
            key = os.path.basename(src_path).replace('.json', '')
            raw_data[key] = json.load(f)
    except Exception as e:
        global_logger.error(f"Failed to merge {src_path}: {str(e)}")

def generate_summary(cve_dir, cve_id, stats, raw_data):
    """Generate summary JSON file"""
    summary = {
        "stats": stats,
        "raw_data": raw_data
    }
    
    try:
        summary_path = os.path.join(cve_dir, f"{cve_id}-all-part1.json")
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        global_logger.info(f"Created summary: {summary_path}")
    except Exception as e:
        global_logger.error(f"Failed to create summary: {str(e)}")

def create_database(cve_db, target_root):
    """Create SQLite database"""
    db_path = os.path.join(target_root, 'cve_database.db')
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS cves
                    (cve_id TEXT PRIMARY KEY,
                     dir TEXT,
                     all_files TEXT,
                     sec_vul TEXT,
                     non_sec_vul TEXT,
                     types TEXT)''')
        
        for cve_id, data in cve_db.items():
            record = (
                cve_id,
                data["dir"],
                json.dumps(sorted(data["all"], key=custom_sort_key)),
                json.dumps(sorted(data["sec_vul"])),
                json.dumps({k: sorted(v) for k, v in data["non_sec_vul"].items()}),
                json.dumps({
                    st: {loc: sorted(files) for loc, files in locs.items()}
                    for st, locs in data["types"].items()
                })
            )
            c.execute("INSERT OR REPLACE INTO cves VALUES (?,?,?,?,?,?)", record)
        
        conn.commit()
        global_logger.info(f"Database created: {db_path}")
        
    except Exception as e:
        global_logger.error(f"Database error: {str(e)}")
    finally:
        if conn:
            conn.close()

def find_original_path(root, filename):
    """Find original file path"""
    for dirpath, _, filenames in os.walk(root):
        if filename in filenames:
            return os.path.join(dirpath, filename)
    return None


if __name__ == "__main__":
    try:
        original_dir = ''
        organized_dir = ''
        organize_cve_files(original_dir, organized_dir)
    except Exception as e:
        global_logger.critical(f"Critical failure: {str(e)}")
        sys.exit(1)
