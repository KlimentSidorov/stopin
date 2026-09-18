"""Record exactly what a basic HTTP client can retrieve from a test gateway."""
import argparse
import json


def probe(session, base_url):
    results = []
    for path in ("/private", "/api/private"):
        response = session.get(base_url + path, timeout=10, allow_redirects=False)
        results.append({"path": path, "status": response.status_code, "body": response.text})
        assert response.status_code == 403 and response.content == b"", results
    return results


if __name__ == "__main__":
    import requests

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    with requests.Session() as session:
        print(json.dumps(probe(session, args.url.rstrip("/")), indent=2))
