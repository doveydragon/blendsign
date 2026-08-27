import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createSessionToken, readTwoFactorChallenge, SESSION_COOKIE } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { decryptSecret } from "@/lib/secrets";
import { clientIp } from "@/lib/clientIp";
import { checkRateLimit } from "@/lib/rateLimit";
import { hashRecoveryCode, verifyTotp } from "@/lib/twoFactor";

const inputSchema = z.object({
  challengeToken: z.string().min(20),
  code: z.string().trim().min(6).max(20),
});

export async function POST(request: NextRequest) {
  const parsed = inputSchema.safeParse(await request.json());
  if (!parsed.success) return NextResponse.json({ error: "Enter a valid authentication code." }, { status: 400 });
  const challenge = readTwoFactorChallenge(parsed.data.challengeToken);
  if (!challenge) return NextResponse.json({ error: "This sign-in attempt has expired. Start again." }, { status: 401 });
  const allowed = await checkRateLimit(`security:2fa:${clientIp(request)}:${challenge.userId}`, 8, 10 * 60);
  if (!allowed) return NextResponse.json({ error: "Too many authentication attempts. Try again in 10 minutes." }, { status: 429 });

  const user = await prisma.user.findUnique({ where: { id: challenge.userId } });
  if (!user?.twoFactorEnabled || !user.twoFactorSecretEncrypted || user.authVersion !== challenge.authVersion) {
    return NextResponse.json({ error: "This sign-in attempt is no longer valid. Start again." }, { status: 401 });
  }

  const validTotp = verifyTotp(parsed.data.code, decryptSecret(user.twoFactorSecretEncrypted));
  const recoveryHash = hashRecoveryCode(parsed.data.code);
  const recoveryIndex = user.twoFactorRecoveryCodeHashes.indexOf(recoveryHash);
  if (!validTotp && recoveryIndex < 0) return NextResponse.json({ error: "The authentication code is incorrect." }, { status: 401 });

  if (recoveryIndex >= 0) {
    await prisma.user.update({
      where: { id: user.id },
      data: { twoFactorRecoveryCodeHashes: user.twoFactorRecoveryCodeHashes.filter((_, index) => index !== recoveryIndex) },
    });
  }

  const response = NextResponse.json({ ok: true, recoveryCodeUsed: recoveryIndex >= 0 });
  response.cookies.set(SESSION_COOKIE, createSessionToken({
    email: challenge.email,
    userId: challenge.userId,
    superAdmin: challenge.superAdmin,
    authVersion: challenge.authVersion,
  }), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 12,
  });
  return response;
}
