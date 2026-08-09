import { NextRequest, NextResponse } from 'next/server';
import { api } from '../../api';
import { cookies } from 'next/headers';
import { isAxiosError } from 'axios';
import { logErrorResponse } from '../../_utils/utils';

type SameSiteValue = 'lax' | 'strict' | 'none';

interface CookieOptions {
  expires?: Date;
  maxAge?: number;
  path?: string;
  domain?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: SameSiteValue;
}

function parseSetCookie(cookieStr: string) {
  const parts = cookieStr.split(';').map(p => p.trim());
  if (parts.length === 0 || !parts[0]) return null;

  const [name, value] = parts[0].split('=');
  if (!name) return null;

  const options: CookieOptions = {};

  for (let i = 1; i < parts.length; i++) {
    const [key, val] = parts[i].split('=');
    const lowerKey = key.toLowerCase();

    if (lowerKey === 'expires') options.expires = new Date(val);
    else if (lowerKey === 'max-age') options.maxAge = Number(val);
    else if (lowerKey === 'path') options.path = val;
    else if (lowerKey === 'domain') options.domain = val;
    else if (lowerKey === 'httponly') options.httpOnly = true;
    else if (lowerKey === 'secure') options.secure = true;
    else if (lowerKey === 'samesite') {
      const sameSiteValue = val.toLowerCase();

      if (sameSiteValue === 'lax' || sameSiteValue === 'strict' || sameSiteValue === 'none') {
        options.sameSite = sameSiteValue;
      }
    }
  }

  return { name: name.trim(), value: decodeURIComponent(value || ''), options };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const apiRes = await api.post('auth/register', body);

    const cookieStore = await cookies();
    const setCookie = apiRes.headers['set-cookie'];

    if (setCookie) {
      const cookieArray = Array.isArray(setCookie) ? setCookie : [setCookie];
      
      for (const cookieStr of cookieArray) {
        const parsed = parseSetCookie(cookieStr);
        if (!parsed) continue;

        // Фильтруем и записываем только нужные куки
        if (parsed.name === 'accessToken' || parsed.name === 'refreshToken') {
          cookieStore.set(parsed.name, parsed.value, parsed.options);
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