from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes.projects import router as projects_router
from app.api.routes.targets import router as targets_router
from app.api.routes.authorization import router as authorization_router
from app.api.routes.auth import router as auth_router

app = FastAPI(
    title="PENTURION API",
    description="Authorized web application security assessment platform",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "application": "PENTURION",
        "version": "0.1.0",
    }


@app.get("/")
def root():
    return {
        "message": "Welcome to PENTURION",
        "docs": "/docs",
    }
app.include_router(projects_router, prefix="/api/v1")
app.include_router(targets_router, prefix="/api/v1")
app.include_router(authorization_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")