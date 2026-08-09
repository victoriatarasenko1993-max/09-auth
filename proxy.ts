import { NextRequest, NextResponse } from 'next/server';
import { checkSession } from '@/lib/api/serverApi';
import { cookies } from 'next/headers';

const privateRoutes = ['/profile', '/notes'];
const publicRoutes = ['/sign-in', '/sign-up'];

export async function proxy(request: NextRequest) {
  const cookieStore = await cookies();
  const { pathname } = request.nextUrl;

  const isPrivateRoute = privateRoutes.some((route) =>
    pathname.startsWith(route)
  );

  const isPublicRoute = publicRoutes.some((route) =>
    pathname.startsWith(route)
  );

  const accessToken = cookieStore.get('accessToken')?.value;
  const refreshToken = cookieStore.get('refreshToken')?.value;

  if (accessToken) {
    if (isPublicRoute) {
      return NextResponse.redirect(new URL('/', request.url));
    }

    return NextResponse.next();
  }

  if (refreshToken) {
    try {
      const session = await checkSession();

      if (!session.data.success) {
        if (isPrivateRoute) {
          return NextResponse.redirect(new URL('/sign-in', request.url));
        }

        return NextResponse.next();
      }

      const response = isPublicRoute
        ? NextResponse.redirect(new URL('/', request.url))
        : NextResponse.next();

      const setCookie = session.headers['set-cookie'];

      if (Array.isArray(setCookie)) {
        setCookie.forEach((cookie) => {
          response.headers.append('Set-Cookie', cookie);
        });
      } else if (setCookie) {
        response.headers.set('Set-Cookie', setCookie);
      }

      return response;
    } catch {
      if (isPrivateRoute) {
        return NextResponse.redirect(new URL('/sign-in', request.url));
      }

      return NextResponse.next();
    }
  }

   if (isPrivateRoute) {
    return NextResponse.redirect(new URL('/sign-in', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/profile/:path*', '/notes/:path*', '/sign-in', '/sign-up'],
  };