import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { authIsConfigured, createSessionToken, createTwoFactorChallenge, SESSION_COOKIE } from "@/lib/auth";
import { ensureDefaultAccount } from "@/lib/account";
import { verifyPassword, timingSafeEqualString } from "@/lib/password";
import { clientIp } from "@/lib/clientIp";
import { checkRateLimit } from "@/lib/rateLimit";
import { sha256 } from "@/lib/secrets";

const inputSchema = z.object({ email: z.string().email(), password: z.string().min(1) });

export async function POST(request: NextRequest) {
  if (!authIsConfigured()) {
    return NextResponse.json({ error: "Admin authentication is not configured on the server." }, { status: 503 });
  }
  const allowed = await checkRateLimit(`login:${clientIp(request)}`, 10, 15 * 60);
  if (!allowed) {
    return NextResponse.json({ error: "Too many login attempts. Try again in a few minutes." }, { status: 429 });
  }
  const parsed = inputSchema.safeParse(await request.json());
  if (!parsed.success) return NextResponse.json({ error: "Enter a valid email address and password." }, { status: 400 });
  const email = parsed.data.email.toLowerCase();
  const accountAllowed = await checkRateLimit(`security:login:${clientIp(request)}:${sha256(email)}`, 8, 15 * 60);
  if (!accountAllowed) return NextResponse.json({ error: "Too many sign-in attempts. Try again in 15 minutes." }, { status: 429 });
  let user;
  let superAdmin = false;
  if (email === process.env.ADMIN_EMAIL?.toLowerCase()) {
    const account = await ensureDefaultAccount();
    user = account.user;
    const validPassword = user.passwordHash
      ? verifyPassword(parsed.data.password, user.passwordHash)
      : timingSafeEqualString(parsed.data.password, process.env.ADMIN_PASSWORD || "");
    if (!validPassword) return NextResponse.json({ error: "Email address or password is incorrect." }, { status: 401 });
    superAdmin = true;
  } else {
    user = await prisma.user.findUnique({ where: { email }, include: { memberships: true } });
    if (!user?.passwordHash || !user.memberships.length || !verifyPassword(parsed.data.password, user.passwordHash)) {
      return NextResponse.json({ error: "Email address or password is incorrect." }, { status: 401 });
    }
  }
  if (user.twoFactorEnabled) {
    if (!user.twoFactorSecretEncrypted) return NextResponse.json({ error: "Two-factor authentication is not configured correctly. Contact an administrator." }, { status: 503 });
    return NextResponse.json({
      requiresTwoFactor: true,
      challengeToken: createTwoFactorChallenge({ email, userId: user.id, superAdmin, authVersion: user.authVersion }),
    });
  }
  const response = NextResponse.json({ ok: true });
  response.cookies.set(SESSION_COOKIE, createSessionToken({ email, userId: user.id, superAdmin, authVersion: user.authVersion }), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 12,
  });
  return response;
}
