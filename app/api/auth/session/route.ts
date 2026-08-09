import { NextRequest, NextResponse } from 'next/server';
import { api } from '../../api';
import { cookies } from 'next/headers';
import { parseSetCookie } from 'next/dist/compiled/@edge-runtime/cookies';
import { isAxiosError } from 'axios';
import { logErrorResponse } from '../../_utils/utils';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();

    const apiRes = await api.post('auth/register', body);

    const cookieStore = await cookies();
    const setCookieHeader = apiRes.headers['set-cookie'];

    if (setCookieHeader) {
      const setCookieHeaders = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
      const parsedCookies = setCookieHeaders.flatMap((cookieHeader) => {
        const cookie = parseSetCookie(cookieHeader);
        return cookie ? [cookie] : [];
      });

      for (const cookie of parsedCookies) {
        if (cookie && (cookie.name === 'accessToken' || cookie.name === 'refreshToken')) {
          cookieStore.set(cookie.name, cookie.value, {
            expires: cookie.expires,
            path: cookie.path,
            maxAge: cookie.maxAge,
            domain: cookie.domain,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            sameSite: cookie.sameSite,
          });
        }
      }
      return NextResponse.json(apiRes.data, { status: apiRes.status });
    }

    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  } catch (error) {
    if (isAxiosError(error)) {
      logErrorResponse(error.response?.data);
      return NextResponse.json(
        { error: error.message, response: error.response?.data },
        { status: error.status }
      );
    }
    logErrorResponse({ message: (error as Error).message });
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}