"""Non-public application responses never become cacheable."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse

from apishield_agent.presentation.response_security import SecurityResponseHeadersMiddleware


def test_api_response_headers_apply_to_success_denial_and_errors():
    app = FastAPI()
    app.add_middleware(SecurityResponseHeadersMiddleware)

    @app.get("/v1/example")
    def sample():
        return {"status": "ok"}

    @app.get("/v1/private")
    def private():
        return JSONResponse({"code": "UNAUTHENTICATED"}, status_code=401)

    with TestClient(app) as client:
        responses = [
            client.get("/v1/example"), client.get("/v1/private"),
            client.get("/v1/not-found"), client.post("/v1/example"),
        ]
    assert [r.status_code for r in responses] == [200, 401, 404, 405]
    for response in responses:
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "microphone=()" in response.headers["permissions-policy"]
