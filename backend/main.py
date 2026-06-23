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
from .cvss_calc import calculate_cvss, get_vector_for_vuln_type
from .crawler import crawl_and_extract
from .mutation_engine import generate_mutations

app = FastAPI(title="Fuzzer API")

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


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
            fuzz_results.extend(results)
            
            for res in results:
                if res.get('status_code') != 404:
                    vuln_type = "Potential Vulnerability"
                    if "SQL" in str(res.get('payload', '')) or "'" in str(res.get('payload', '')):
                        vuln_type = "SQL Injection"
                    elif "<script>" in str(res.get('payload', '')):
                        vuln_type = "XSS"
                    elif "../" in str(res.get('payload', '')):
                        vuln_type = "Path Traversal"

                    vector = get_vector_for_vuln_type(vuln_type)
                    cvss_score = calculate_cvss(vector)
                    
                    global current_max_cvss
                    if cvss_score > current_max_cvss:
                        current_max_cvss = cvss_score
                    
                    severity = "Low"
                    if cvss_score >= 9.0: severity = "Critical"
                    elif cvss_score >= 7.0: severity = "High"
                    elif cvss_score >= 4.0: severity = "Moderate"
                    
                    finding = Finding(
                        scan_id=scan.id,
                        vuln_type=vuln_type,
                        severity=severity,
                        score=cvss_score,
                        payload=res.get('payload'),
                        payload_hash=hashlib.sha256(str(res.get('payload')).encode()).hexdigest(),
                        raw_request=f"{res.get('method', 'GET')} {res.get('url')} HTTP/1.1",
                        raw_response=f"Status: {res.get('status_code')}\nLength: {res.get('length')}"
                    )
                    db.add(finding)
            
            scan.end_time = datetime.utcnow()
            scan.total_findings = len(results)
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
    return {
        "is_running": fuzzer_instance.is_running,
        "completed_requests": fuzzer_instance.completed_requests,
        "total_requests": fuzzer_instance.total_requests,
        "max_cvss": current_max_cvss,
        "results": fuzz_results
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

# Mount static files
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
async def serve_index():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8080, reload=False)
