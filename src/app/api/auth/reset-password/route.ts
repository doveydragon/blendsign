import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { hashPassword, verifyPassword } from "@/lib/password";
import { passwordPolicyError } from "@/lib/passwordPolicy";
import { clientIp } from "@/lib/clientIp";
import { checkRateLimit } from "@/lib/rateLimit";
import { sha256 } from "@/lib/secrets";

const inputSchema = z.object({ token: z.string().min(20), password: z.string().max(200) });

export async function POST(request: NextRequest) {
  const parsed = inputSchema.safeParse(await request.json());
  if (!parsed.success) return NextResponse.json({ error: "The reset request is invalid." }, { status: 400 });
  const allowed = await checkRateLimit(`security:reset-submit:${clientIp(request)}`, 10, 30 * 60);
  if (!allowed) return NextResponse.json({ error: "Too many reset attempts. Try again in 30 minutes." }, { status: 429 });
  const policyError = passwordPolicyError(parsed.data.password);
  if (policyError) return NextResponse.json({ error: policyError }, { status: 400 });

  const reset = await prisma.passwordResetToken.findUnique({ where: { tokenHash: sha256(parsed.data.token) }, include: { user: true } });
  if (!reset || reset.usedAt || reset.expiresAt <= new Date()) {
    return NextResponse.json({ error: "This reset link is invalid or has expired. Request a new one." }, { status: 400 });
  }
  if (reset.user.passwordHash && verifyPassword(parsed.data.password, reset.user.passwordHash)) {
    return NextResponse.json({ error: "Choose a password you have not just been using." }, { status: 400 });
  }

  await prisma.$transaction([
    prisma.user.update({ where: { id: reset.userId }, data: { passwordHash: hashPassword(parsed.data.password), authVersion: { increment: 1 } } }),
    prisma.passwordResetToken.updateMany({ where: { userId: reset.userId, usedAt: null }, data: { usedAt: new Date() } }),
  ]);
  return NextResponse.json({ ok: true });
}
