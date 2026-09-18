"""Replay challenge submissions and document transferable bearer-cookie behavior."""
import argparse
import json


def probe(session_factory, base_url):
    with session_factory() as first, session_factory() as second:
        challenge = first.post(base_url + "/challenge", timeout=10).json()
        verify_url = base_url + "/challenge/verify"
        assert second.post(verify_url, json=challenge, timeout=10).status_code == 403
        assert first.post(verify_url, json=challenge, timeout=10).status_code == 200
        # Restore the original binding cookie so rejection tests consumed state.
        replay_cookie = "gateway_challenge_session=" + challenge["session_id"]
        assert first.post(verify_url, json=challenge, headers={"Cookie": replay_cookie},
                          timeout=10).status_code == 403
        token = first.cookies.get("gateway_session")
        assert token
        copied = second.get(base_url + "/private", timeout=10,
                            headers={"Cookie": "gateway_session=" + token})
        assert copied.status_code == 200
        second.cookies.clear()
        tampered = second.get(base_url + "/private", timeout=10,
                              headers={"Cookie": "gateway_session=" + token + "x"})
        assert tampered.status_code == 403 and tampered.content == b""
        return {"cross_session_challenge": "blocked", "consumed_challenge_replay": "blocked",
                "tampered_cookie": "blocked", "copied_valid_bearer_cookie": "allowed",
                "limitation": "Access cookies are reusable bearer credentials until expiry/revocation."}


if __name__ == "__main__":
    import requests

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    print(json.dumps(probe(requests.Session, args.url.rstrip("/")), indent=2))
