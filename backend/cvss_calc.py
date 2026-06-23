from cvss import CVSS3

def calculate_cvss(vector_string: str) -> float:
    """
    Calculates the CVSS 3.1 base score from a vector string.
    Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
    """
    try:
        c = CVSS3(vector_string)
        return c.base_score
    except Exception as e:
        print(f"Error calculating CVSS: {e}")
        return 0.0

def get_vector_for_vuln_type(vuln_type: str) -> str:
    """
    Maps a vulnerability type (e.g., 'SQL Injection') to a CVSS 3.1 vector string.
    We can expand this dictionary as we add more vulnerability types.
    """
    vectors = {
        "SQL Injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # 9.8 Critical
        "XSS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", # 6.1 Medium
        "Path Traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", # 7.5 High
        "Command Injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", # 9.8 Critical
        "Open Redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", # 6.1 Medium
    }
    # Default to a low/medium severity if unknown, e.g., information disclosure
    return vectors.get(vuln_type, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
