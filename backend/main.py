from pathlib import Path
from anyio import to_thread
from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
import os
import uvicorn
from .fuzzer import fuzzer_instance
import asyncio
from datetime import datetime
import hashlib
from .database import engine, Base, SessionLocal, Target, Scan, Finding
import re
from .cvss_calc import calculate_cvss, get_vector_for_vuln_type
from .crawler import crawl_and_extract
from .mutation_engine import generate_mutations

from contextlib import asynccontextmanager

app = FastAPI(title="Fuzzer API")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic: create database tables
    Base.metadata.create_all(bind=engine)
    yield
    # Shutdown logic (if any) can be added here

app = FastAPI(title="Fuzzer API", lifespan=lifespan)

class FuzzRequest(BaseModel):
    target_url: str
    intensity: str = "regular"
    delay_ms: int = 100

class FuzzResponse(BaseModel):
    status: str
    message: str

# In-memory storage for results (for demo purposes)
fuzz_results = []
current_max_cvss = 0.0
current_task = None

@app.post("/api/start")
async def start_fuzzing(req: FuzzRequest, background_tasks: BackgroundTasks):
    global fuzz_results, current_task, current_max_cvss
    fuzz_results = []
    current_max_cvss = 0.0
    
    if fuzzer_instance.is_running:
        return {"status": "error", "message": "Fuzzer is already running."}
        
    fuzzer_instance.is_running = True
        
    async def task_runner():
        global fuzz_results
        
        db = SessionLocal()
        try:
            target = db.query(Target).filter(Target.url == req.target_url).first()
            if not target:
                target = Target(url=req.target_url)
                db.add(target)
                db.commit()
                db.refresh(target)
                
            scan = Scan(target_id=target.id, profile_type=req.intensity)
            db.add(scan)
            db.commit()
            db.refresh(scan)

            # 1. Discover all endpoints
            discovered_urls = await crawl_and_extract(req.target_url)
            
            # 2. Mutate all endpoints based on detected parameter types
            all_mutated_requests = []
            for d_url in discovered_urls:
                mutated_requests = generate_mutations(d_url, req.intensity)
                all_mutated_requests.extend(mutated_requests)

            # 3. Fire the fuzzer
            results = await fuzzer_instance.run_fuzz(all_mutated_requests, req.delay_ms, req.target_url)
            
            # Compute statistical properties of the response lengths (only for valid responses, i.e., status_code > 0)
            valid_lengths = [res["length"] for res in results if res.get("status_code", 0) > 0]
            
            mean_len = 0.0
            std_dev_len = 0.0
            if valid_lengths:
                mean_len = sum(valid_lengths) / len(valid_lengths)
                variance = sum((x - mean_len) ** 2 for x in valid_lengths) / len(valid_lengths)
                std_dev_len = variance ** 0.5

            # Dictionary of common regexes for database errors
            sql_error_patterns = [
                r"you have an error in your sql syntax",
                r"unclosed quotation mark",
                r"mysql_fetch_array",
                r"pg_query\(\)",
                r"sqlite3\.OperationalError",
                r"ora-\d+",
                r"mariadb server version",
                r"syntax error at or near",
                r"driver error"
            ]
            
            sql_regex = re.compile("|".join(sql_error_patterns), re.IGNORECASE)
            
            findings_count = 0
            
            for res in results:
                # Add stats analysis to result dictionary for retrieval by API/frontend
                length = res.get("length", 0)
                status_code = res.get("status_code", 0)
                response_body = res.get("response_body", "")
                payload = res.get("payload", "")
                
                # Calculate Z-score
                z_score = 0.0
                if std_dev_len > 0:
                    z_score = (length - mean_len) / std_dev_len
                
                res["z_score"] = round(z_score, 2)
                res["vuln_type"] = None
                
                # We skip checking anomalies/findings for 404 responses
                if status_code == 404 or status_code == 0:
                    continue

                # Signature checks
                has_sql_error = bool(sql_regex.search(response_body))
                has_xss_reflection = payload and (payload in response_body) and (("<script>" in payload) or ("onerror" in payload) or ("onload" in payload))
                has_path_traversal = ("root:x:0:0" in response_body) or ("[fonts]" in response_body.lower() and "extensions" in response_body.lower())
                
                # Classification rules
                vuln_type = None
                severity = "Low"
                
                if has_xss_reflection and abs(z_score) >= 2.5:
                    vuln_type = "Reflected XSS"
                elif has_sql_error:
                    vuln_type = "SQL Injection"
                elif has_path_traversal:
                    vuln_type = "Path Traversal"
                elif status_code == 500 and abs(z_score) >= 2.5:
                    vuln_type = "Internal Server Error / Potential Code Injection"
                elif abs(z_score) >= 2.5:
                    # Purely statistical length anomaly
                    vuln_type = "Anomalous Response Length"
                    severity = "Moderate"
                
                if vuln_type:
                    res["vuln_type"] = vuln_type
                    vector = get_vector_for_vuln_type("SQL Injection" if vuln_type == "SQL Injection" else 
                                                      ("XSS" if vuln_type == "Reflected XSS" else 
                                                       ("Path Traversal" if vuln_type == "Path Traversal" else vuln_type)))
                    cvss_score = calculate_cvss(vector)
                    
                    global current_max_cvss
                    if cvss_score > current_max_cvss:
                        current_max_cvss = cvss_score
                    
                    if vuln_type in ["SQL Injection", "Path Traversal"]:
                        severity = "High" if vuln_type == "Path Traversal" else "Critical"
                    elif vuln_type == "Reflected XSS":
                        severity = "Moderate"
                    
                    finding = Finding(
                        scan_id=scan.id,
                        vuln_type=vuln_type,
                        severity=severity,
                        score=cvss_score,
                        payload=payload,
                        payload_hash=hashlib.sha256(str(payload).encode()).hexdigest(),
                        raw_request=f"{res.get('method', 'GET')} {res.get('url')} HTTP/1.1",
                        raw_response=f"Status: {status_code}\nLength: {length}\nZ-Score: {res['z_score']}\nBody Snippet: {response_body[:200]}"
                    )
                    db.add(finding)
                    findings_count += 1
            
            fuzz_results.extend(results)
            scan.end_time = datetime.utcnow()
            scan.total_findings = findings_count
            db.commit()

        except Exception as e:
            print(f"Error during fuzzing: {e}")
        finally:
            fuzzer_instance.is_running = False
            db.close()

            
    current_task = asyncio.create_task(task_runner())
    return {"status": "success", "message": "Fuzzing started."}

@app.post("/api/stop")
async def stop_fuzzing():
    fuzzer_instance.stop()
    return {"status": "success", "message": "Fuzzing stopped."}

@app.get("/api/results")
async def get_results():
    # Remove large response body strings to optimize payload size in results API
    sanitized_results = []
    for r in fuzz_results:
        sanitized_r = r.copy()
        if "response_body" in sanitized_r:
            del sanitized_r["response_body"]
        sanitized_results.append(sanitized_r)
        
    return {
        "is_running": fuzzer_instance.is_running,
        "completed_requests": fuzzer_instance.completed_requests,
        "total_requests": fuzzer_instance.total_requests,
        "max_cvss": current_max_cvss,
        "results": sanitized_results
    }

@app.get("/api/scans")
async def get_scans():
    db = SessionLocal()
    try:
        scans = db.query(Scan).order_by(Scan.start_time.desc()).all()
        results = []
        for scan in scans:
            target = db.query(Target).filter(Target.id == scan.target_id).first()
            findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
            max_cvss = max([f.score for f in findings]) if findings else 0.0
            
            results.append({
                "id": scan.id,
                "url": target.url if target else "Unknown",
                "mode": scan.profile_type,
                "start_time": scan.start_time.isoformat() if scan.start_time else "",
                "total_findings": scan.total_findings,
                "max_cvss": max_cvss
            })
        return {"status": "success", "scans": results}
    finally:
        db.close()

# Mount static files — use pathlib for reliable resolution regardless of CWD
# (os.path.dirname(__file__) can be relative/wrong on cloud platforms like Render)
frontend_dir = str(Path(__file__).resolve().parent.parent / "frontend")
print(f"[INFO] Serving static files from: {frontend_dir}")
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
async def serve_index():
    return FileResponse(str(Path(frontend_dir) / "index.html"))

if __name__ == "__main__":
    port = int(os.getenv("FASTAPI_PORT", "8081"))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True)
