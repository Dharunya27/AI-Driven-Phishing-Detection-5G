"""
FastAPI REST API Service for Phishing URL Detection
Sriwijaya University / Dinas KOMINFO Kota Prabumulih Research
Author: M. Athallah Rafif Aldera
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from src.predictor import PhishingPredictor

app = FastAPI(
    title="Phishing Detection REST API",
    description="Machine Learning service for real-time lexical URL phishing detection.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize shared predictor instance
predictor = PhishingPredictor()


class URLRequest(BaseModel):
    url: str = Field(..., description="Target URL string to evaluate", example="https://prabumulihkota.go.id")
    threshold: Optional[float] = Field(0.5, description="Decision threshold for phishing classification", ge=0.0, le=1.0)


class BatchURLRequest(BaseModel):
    urls: List[str] = Field(..., description="List of target URLs to evaluate")
    threshold: Optional[float] = Field(0.5, ge=0.0, le=1.0)


@app.get("/", tags=["General"])
def root_status():
    return {
        "service": "Phishing Detection API",
        "version": "1.0.0",
        "author": "M. Athallah Rafif Aldera",
        "institution": "Universitas Sriwijaya & Diskominfo Kota Prabumulih",
        "model": "Random Forest Classifier (10 Estimators)",
        "status": "operational",
        "documentation": "/docs"
    }


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "service": "phishing-detector-api"}


@app.post("/predict", tags=["Inference"])
def predict_single_url(payload: URLRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL field cannot be empty.")
    try:
        result = predictor.predict(payload.url, threshold=payload.threshold)
        return result
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@app.post("/batch-predict", tags=["Inference"])
def predict_batch_urls(payload: BatchURLRequest):
    if not payload.urls:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URLs list cannot be empty.")
    try:
        results = predictor.predict_batch(payload.urls, threshold=payload.threshold)
        return {
            "total_processed": len(results),
            "results": results
        }
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
