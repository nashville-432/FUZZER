import re
from urllib.parse import urlparse, urlencode
from .database import SessionLocal, Payload

def detect_type(value: str) -> str:
    """Detects the likely data type of a parameter value."""
    if not value:
        return "String"
        
    # Boolean
    if value.lower() in ['true', 'false']:
        return "Boolean"
        
    # Integer
    if re.match(r'^-?\d+$', value):
        return "Integer"
        
    # Path
    if '/' in value or '\\' in value or value.endswith('.php') or value.endswith('.html'):
        return "Path"
        
    # JSON/XML heuristic
    if value.startswith('{') or value.startswith('['):
        return "JSON"
    if value.startswith('<'):
        return "XML"
        
    return "String"

def get_payloads(data_type: str, intensity: str) -> list[str]:
    """Fetches payloads from the database based on type and intensity."""
    db = SessionLocal()
    try:
        # Determine limit based on intensity
        if intensity == "passive":
            limit = 25
        elif intensity == "regular":
            limit = 60
        else: # aggressive
            limit = 120

        # Query database
        payloads = db.query(Payload).filter(Payload.data_type == data_type).limit(limit).all()
        
        # Fallback to String if the specific type doesn't have enough payloads
        if not payloads and data_type != "String":
            payloads = db.query(Payload).filter(Payload.data_type == "String").limit(limit).all()
            
        payload_texts = [p.payload_text for p in payloads]
        
        # Inject custom hyper-aggressive mutation errors/syntax breakers on top of DB
        extra_breakers = []
        if data_type == "Integer":
            # Add integer overflow/underflow, characters causing type errors
            extra_breakers = ["-1", "99999999999999999999", "0.0000001", "NaN", "null", "undefined", "''", "'", '"', "\\"]
        elif data_type == "String":
            # Bad formatting syntax & SQL syntax breakers
            extra_breakers = ["'", "\"", "`", ") OR 1=1--", "' OR 'a'='a", "\" OR \"a\"=\"a", "';--", "\\", "\x00", "%00"]
            
        # Combine and ensure uniqueness, keeping database payloads first
        combined = []
        for p in payload_texts + extra_breakers:
            if p not in combined:
                combined.append(p)
        return combined[:limit]
    finally:
        db.close()

def generate_mutations(req_data: dict, intensity: str) -> list[dict]:
    """
    Takes a structured request dictionary (with method and params)
    and returns a list of dictionaries ready for the fuzzer engine.
    """
    mutated_requests = []
    base_url = req_data["url"]
    method = req_data["method"]
    params = req_data["params"]
    
    if not params:
        # Fuzz the path itself
        payloads = get_payloads("String", intensity)
        base = base_url if base_url.endswith('/') else base_url + '/'
        for p in payloads:
            mutated_requests.append({
                "url": base + str(p),
                "method": method,
                "data": None,
                "payload": str(p)
            })
        return mutated_requests

    # Iterate through every parameter and generate mutations
    for param, original_value in params.items():
        data_type = detect_type(str(original_value))
        payloads = get_payloads(data_type, intensity)
        
        for payload in payloads:
            new_params = params.copy()
            new_params[param] = payload
            
            if method == "GET":
                new_query = urlencode(new_params, doseq=True)
                if "?" in base_url:
                    mutated_url = base_url.split("?")[0] + "?" + new_query
                else:
                    mutated_url = base_url + "?" + new_query
                
                mutated_requests.append({
                    "url": mutated_url,
                    "method": "GET",
                    "data": None,
                    "payload": payload
                })
            else:
                mutated_requests.append({
                    "url": base_url,
                    "method": method,
                    "data": new_params,
                    "payload": payload
                })
            
    return mutated_requests
