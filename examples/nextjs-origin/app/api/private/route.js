export const dynamic = 'force-dynamic';
export async function GET(request) {
  return Response.json({protected: 'NEXTJS-PROTECTED-ORIGIN-CONTENT',
    originSecretVisible: request.headers.has('x-gateway-origin-secret')});
}
