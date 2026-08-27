import { NextRequest, NextResponse } from "next/server";
import { randomBytes } from "crypto";
import { z } from "zod";
import { ensureDefaultAccount } from "@/lib/account";
import { sendPasswordResetEmail } from "@/lib/authMail";
import { clientIp } from "@/lib/clientIp";
import { prisma } from "@/lib/prisma";
import { checkRateLimit } from "@/lib/rateLimit";
import { sha256 } from "@/lib/secrets";

const inputSchema = z.object({ email: z.string().email() });
const genericMessage = "If that account exists, a password reset link has been sent.";

export async function POST(request: NextRequest) {
  const parsed = inputSchema.safeParse(await request.json());
  if (!parsed.success) return NextResponse.json({ error: "Enter a valid email address." }, { status: 400 });
  const email = parsed.data.email.toLowerCase();
  const allowedByIp = await checkRateLimit(`security:reset-ip:${clientIp(request)}`, 8, 60 * 60);
  const allowedByAccount = await checkRateLimit(`security:reset-account:${sha256(email)}`, 3, 60 * 60);
  if (!allowedByIp || !allowedByAccount) return NextResponse.json({ message: genericMessage }, { status: 202 });

  if (email === process.env.ADMIN_EMAIL?.toLowerCase()) await ensureDefaultAccount();
  const user = await prisma.user.findUnique({
    where: { email },
    include: { org: true, memberships: { include: { org: true }, take: 1 } },
  });
  if (!user) return NextResponse.json({ message: genericMessage }, { status: 202 });

  const token = randomBytes(32).toString("base64url");
  const tokenHash = sha256(token);
  await prisma.$transaction([
    prisma.passwordResetToken.updateMany({ where: { userId: user.id, usedAt: null }, data: { usedAt: new Date() } }),
    prisma.passwordResetToken.create({ data: { userId: user.id, tokenHash, expiresAt: new Date(Date.now() + 30 * 60 * 1000) } }),
  ]);
  try {
    await sendPasswordResetEmail(user, user.org || user.memberships[0]?.org || null, token);
  } catch (error) {
    console.error("Unable to send password reset email", error);
    await prisma.passwordResetToken.deleteMany({ where: { tokenHash } });
  }
  return NextResponse.json({ message: genericMessage }, { status: 202 });
}
