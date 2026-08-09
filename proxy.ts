import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { checkSession } from "./lib/api/serverApi";

const SIGN_IN_PATH = "/sign-in";
const AUTH_TOKEN_KEY = "accessToken";
const REFRESH_TOKEN_KEY = "refreshToken";
const PRIVATE_ROUTES = ["/profile", "/notes"];
const PUBLIC_ROUTES = ["/sign-in", "/sign-up", "/"];

export const config = {
  matcher: ["/notes/:path*", "/profile/:path*", "/sign-in", "/sign-up"],
};

export default async function proxy(request: NextRequest) {
  const cookieStore = await cookies();
  let accessToken = cookieStore.get(AUTH_TOKEN_KEY)?.value;
  const refreshToken = cookieStore.get(REFRESH_TOKEN_KEY)?.value;

  const { pathname } = request.nextUrl;
  console.log(`[Proxy Guard]: Route -> ${pathname} | Token Active -> ${!!accessToken}`);

  let responseWithNewCookies: NextResponse | null = null;

  if (!accessToken && refreshToken) {
    try {
      const response = await checkSession();

      if (response && response.status === 200) {
        responseWithNewCookies = NextResponse.next();

        const rawSetCookie = response.headers["set-cookie"];
        let setCookieHeader: string[] = [];

        if (rawSetCookie) {
          if (Array.isArray(rawSetCookie)) {
            setCookieHeader = rawSetCookie;
          } else {
            setCookieHeader = [rawSetCookie];
          }
        }

        setCookieHeader.forEach((cookieStr) => {

          responseWithNewCookies?.headers.append("Set-Cookie", cookieStr);

          const cookiePair = cookieStr.split(";")[0];
          if (cookiePair) {
            const equalSignIndex = cookiePair.indexOf("=");
            if (equalSignIndex !== -1) {
              const key = cookiePair.substring(0, equalSignIndex).trim();
              const value = cookiePair.substring(equalSignIndex + 1).trim();

              responseWithNewCookies?.cookies.set(key, value, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "lax",
                path: "/",
              });

              if (key === AUTH_TOKEN_KEY) {
                accessToken = value;
              }
            }
          }
        });

        console.log(`[Proxy Guard]: Session successfully restored via checkSession()`);
      }
    } catch (error) {
      console.error("[Proxy Guard]: Session validation failed or expired:", error);
    }
  }

  const isPrivate = PRIVATE_ROUTES.some((route) => pathname.startsWith(route));
  if (isPrivate && !accessToken) {
    const loginUrl = new URL(SIGN_IN_PATH, request.url);
    return NextResponse.redirect(loginUrl);
  }

  const isPublic = PUBLIC_ROUTES.some((route) => pathname === route);
  if (isPublic && accessToken) {
    if (pathname !== "/") {
      const homeUrl = new URL("/", request.url);
      const redirectResponse = NextResponse.redirect(homeUrl);

      if (responseWithNewCookies) {
        responseWithNewCookies.headers.forEach((value, key) => {
          if (key.toLowerCase() === "set-cookie") {
            redirectResponse.headers.append(key, value);
          }
        });

        responseWithNewCookies.cookies.getAll().forEach((cookie) => {
          redirectResponse.cookies.set(cookie.name, cookie.value, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/",
          });
        });
      }
      return redirectResponse;
    }
  }

  return responseWithNewCookies || NextResponse.next();
}