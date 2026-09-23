"""Conservative crawler classification from self-declared HTTP identity.

User-Agent classification is useful for policy and analytics, but is not verified
identity: any client can spoof or omit it. Stronger DNS/IP verification can be added
per crawler family without changing the route-policy interface.
"""

AI_CRAWLERS = {
    "gptbot": "GPTBot",
    "chatgpt-user": "ChatGPT-User",
    "oai-searchbot": "OAI-SearchBot",
    "claudebot": "ClaudeBot",
    "claude-web": "Claude-Web",
    "anthropic-ai": "anthropic-ai",
    "google-extended": "Google-Extended",
    "google-cloudvertexbot": "Google-CloudVertexBot",
    "bytespider": "Bytespider",
    "ccbot": "CCBot",
    "meta-externalagent": "Meta-ExternalAgent",
    "cohere-ai": "cohere-ai",
    "perplexitybot": "PerplexityBot",
    "mistralai-user": "MistralAI-User",
}

SEARCH_CRAWLERS = {
    "googlebot": "Googlebot",
    "bingbot": "Bingbot",
    "duckduckbot": "DuckDuckBot",
    "yandexbot": "YandexBot",
    "baiduspider": "Baiduspider",
}

GENERIC_AUTOMATION = {
    "python-requests": "python-requests",
    "curl/": "curl",
    "wget/": "wget",
    "httpx/": "httpx",
    "aiohttp/": "aiohttp",
}


def classify_user_agent(user_agent: str | None) -> dict:
    value = (user_agent or "").lower()
    for needle, name in AI_CRAWLERS.items():
        if needle in value:
            return {"identity": name, "category": "ai", "verified": False,
                    "source": "self_declared_user_agent"}
    for needle, name in SEARCH_CRAWLERS.items():
        if needle in value:
            return {"identity": name, "category": "search", "verified": False,
                    "source": "self_declared_user_agent"}
    for needle, name in GENERIC_AUTOMATION.items():
        if needle in value:
            return {"identity": name, "category": "automation", "verified": False,
                    "source": "user_agent_pattern"}
    return {"identity": "unverified", "category": "unknown", "verified": False,
            "source": "none"}
