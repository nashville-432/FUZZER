from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the intentionally vulnerable test server!"}

@app.get("/search")
def search(query: str = ""):
    # Intentionally crash the server (500 Error) if the fuzzer injects SQL syntax or quotes!
    if "'" in query or '"' in query or ";" in query or "OR" in query.upper():
        raise HTTPException(status_code=500, detail="FATAL DB ERROR: syntax error at or near injected payload!")
    
    return {"results": f"Showing search results for: {query}"}

@app.get("/user/{user_id}")
def get_user(user_id: int):
    # This will throw a standard 422 Unprocessable Entity (similar to a 400 error)
    # if the fuzzer injects text into this integer-only path!
    return {"user": f"User {user_id} data"}

@app.get("/admin/hidden")
def admin_panel():
    # Intentionally return a 403 Forbidden
    raise HTTPException(status_code=403, detail="Access Denied.")

@app.get("/old-api")
def missing_api():
    # Intentionally return a 404 Not Found
    raise HTTPException(status_code=404, detail="This API endpoint no longer exists.")

if __name__ == "__main__":
    print("Vulnerable Target Dummy is running on http://127.0.0.1:9000")
    print("Point your fuzzer at: http://127.0.0.1:9000/search?query=test")
    uvicorn.run(app, host="127.0.0.1", port=9000)
