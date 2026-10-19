import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SVS-Cyber Backend Bridge")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "healthy", "protection_service": "active"}

@app.get("/api/device/activity")
def device_activity():
    return {
        "status": "online",
        "filter_driver": "active",
        "protection_service": "running",
        "rule_package": "loaded",
        "network_telemetry": "active",
        "totals": {"detected": 0, "blocked": 0, "quarantined": 0}
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=6764)
