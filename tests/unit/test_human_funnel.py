from gateway.dashboard import evaluate_dashboard
from gateway.detection.crawler_identity import classify_user_agent
from gateway.detection.signals import Signals
from gateway.policies.evaluator import Decision


def signals(*, valid=False, html=True, category='unknown', browser_navigation=False):
    return Signals(request={'html_navigation': html, 'browser_navigation': browser_navigation},
                   session={'valid': valid},
                   crawler={'identity': 'test', 'category': category, 'verified': False})


def test_crawler_classifier_separates_declared_ai_search_and_http_tools():
    assert classify_user_agent('Mozilla/5.0 compatible; GPTBot/1.2')['category'] == 'ai'
    assert classify_user_agent('ClaudeBot/1.0')['category'] == 'ai'
    assert classify_user_agent('Googlebot/2.1')['category'] == 'search'
    assert classify_user_agent('python-requests/2.32')['category'] == 'automation'
    assert classify_user_agent('Mozilla/5.0 Chrome/153.0')['category'] == 'unknown'


def test_public_route_is_open_but_human_route_bootstraps_browser_session():
    public = {'strictness': 'balanced', 'routes': [{'pattern': '/', 'action': 'public'}]}
    assert evaluate_dashboard(signals(category='ai'), public, '/')[0] == Decision.ALLOW

    human = {'strictness': 'balanced', 'routes': [{'pattern': '/contact', 'action': 'human'}]}

    decision, reasons = evaluate_dashboard(signals(), human, '/contact')
    assert decision == Decision.BLOCK
    assert 'route_requires_browser_navigation' in reasons

    decision, reasons = evaluate_dashboard(
        signals(browser_navigation=True), human, '/contact'
    )
    assert decision == Decision.CHALLENGE
    assert 'route_transparent_session_bootstrap' in reasons

    for category in ('ai', 'search', 'automation'):
        decision, reasons = evaluate_dashboard(
            signals(category=category, browser_navigation=True), human, '/contact'
        )
        assert decision == Decision.BLOCK
        assert f'route_human_only_{category}' in reasons


def test_human_route_allows_verified_session_and_blocks_unverified_api():
    policy = {'strictness': 'balanced', 'routes': [{'pattern': '/api/private/*', 'action': 'human'}]}
    assert evaluate_dashboard(signals(valid=True, html=False), policy, '/api/private/data')[0] == Decision.ALLOW
    assert evaluate_dashboard(signals(valid=False, html=False), policy, '/api/private/data')[0] == Decision.BLOCK


def test_invalid_session_cannot_be_overridden_by_public_route():
    policy = {'strictness': 'balanced', 'routes': [{'pattern': '/', 'action': 'public'}]}
    invalid = signals()
    invalid.session['invalid_token'] = True
    assert evaluate_dashboard(invalid, policy, '/')[0] == Decision.BLOCK
