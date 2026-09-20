"""ASGI boundary limits and bounded-cardinality, shared request metrics."""
from collections import OrderedDict, Counter
import hashlib
import hmac
import time
from ipaddress import ip_address

from redis.exceptions import RedisError
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response


class RequestControls:
    INCREMENT = """
    local n = redis.call('INCR', KEYS[1])
    if n == 1 then redis.call('EXPIRE', KEYS[1], 60) end
    return {n, redis.call('TTL', KEYS[1])}
    """

    def __init__(self, settings, redis=None):
        self.settings, self.redis = settings, redis
        self.prefix = f"stopin:{settings.site_id}:"
        self.buckets = OrderedDict()
        self.counts = Counter()

    def allow(self, address, challenge=False):
        identity = hmac.new(self.settings.token_secret.encode(), address.encode(), hashlib.sha256).hexdigest()
        key = self.prefix + ('challenge-rate:' if challenge else 'rate:') + identity
        limit = self.settings.challenge_rate_limit if challenge else self.settings.rate_limit
        if self.redis is not None:
            count, ttl = self.redis.eval(self.INCREMENT, 1, key)
        else:
            now = time.monotonic()
            while self.buckets and next(iter(self.buckets.values()))[1] <= now:
                self.buckets.popitem(last=False)
            if key not in self.buckets:
                if len(self.buckets) >= 10000:
                    return False, 60
                self.buckets[key] = [0, now + 60]
            self.buckets[key][0] += 1
            count, expires = self.buckets[key]
            ttl = max(1, int(expires - now))
        return count <= limit, max(1, ttl)

    def observe(self, status):
        label = str(status // 100) + 'xx'
        if label not in ('1xx', '2xx', '3xx', '4xx', '5xx'):
            label = '5xx'
        if self.redis is not None:
            self.redis.hincrby(self.prefix + 'metrics', label, 1)
        else:
            self.counts[label] += 1

    def metrics(self):
        counts = self.redis.hgetall(self.prefix + 'metrics') if self.redis is not None else self.counts
        lines = ['# HELP stopin_requests_total Completed gateway requests.',
                 '# TYPE stopin_requests_total counter']
        for label in ('1xx', '2xx', '3xx', '4xx', '5xx'):
            lines.append(f'stopin_requests_total{{site="{self.settings.site_id}",status="{label}"}} {int(counts.get(label, 0))}')
        return '\n'.join(lines) + '\n'


class BoundaryMiddleware:
    def __init__(self, app, controls):
        self.app, self.controls = app, controls

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        status = 500

        async def tracked_send(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = message['status']
            await send(message)

        async def reject(code, retry=None):
            headers = {'Cache-Control': 'no-store'}
            if retry:
                headers['Retry-After'] = str(retry)
            await Response(status_code=code, headers=headers)(scope, receive, tracked_send)

        try:
            if scope['path'] not in ('/health', '/ready', '/metrics'):
                address = (scope.get('client') or ('unknown', 0))[0]
                if self.controls.settings.trust_railway_proxy:
                    # Only enable behind Railway's HTTP edge, with every private
                    # network peer trusted. Never enable on a directly exposed port.
                    headers = dict(scope.get('headers', []))
                    try:
                        address = str(ip_address(headers.get(b'x-real-ip', b'').decode('ascii')))
                    except (ValueError, UnicodeError):
                        return await reject(400)
                allowed, retry = await run_in_threadpool(self.controls.allow, address)
                if not allowed:
                    return await reject(429, retry)
                if scope['path'] == '/challenge' and scope['method'] == 'POST':
                    allowed, retry = await run_in_threadpool(self.controls.allow, address, True)
                    if not allowed:
                        return await reject(429, retry)
            # Count actual ASGI bytes: Content-Length alone is not trustworthy.
            body = bytearray()
            limit = 16384 if scope['path'] == '/challenge/verify' else self.controls.settings.max_body_bytes
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    return
                body.extend(message.get('body', b''))
                if len(body) > limit:
                    return await reject(413)
                if not message.get('more_body', False):
                    break
            delivered = False

            async def buffered_receive():
                nonlocal delivered
                if not delivered:
                    delivered = True
                    return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
                return await receive()

            await self.app(scope, buffered_receive, tracked_send)
        except RedisError:
            await reject(503)
        finally:
            if scope['path'] not in ('/health', '/ready', '/metrics'):
                try:
                    await run_in_threadpool(self.controls.observe, status)
                except RedisError:
                    pass  # An unavailable metrics backend must not change the response.
