import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getRequestContext } from "@/lib/account";
import { prisma } from "@/lib/prisma";
import { decryptSecret, encryptSecret } from "@/lib/secrets";
import { authenticatorUri, generateRecoveryCodes, generateTwoFactorSecret, hashRecoveryCode, verifyTotp } from "@/lib/twoFactor";

const QRCode = require("qrcode");
const codeSchema = z.object({ code: z.string().trim().min(6).max(20) });

export async function GET() {
  const context = await getRequestContext();
  if (!context) return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  return NextResponse.json({
    enabled: context.user.twoFactorEnabled,
    recoveryCodesRemaining: context.user.twoFactorRecoveryCodeHashes.length,
  });
}

export async function POST() {
  const context = await getRequestContext();
  if (!context) return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  if (context.user.twoFactorEnabled) return NextResponse.json({ error: "Two-factor authentication is already enabled." }, { status: 400 });
  const secret = generateTwoFactorSecret();
  const uri = authenticatorUri(context.user.email, secret);
  const qrCode = await QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 1, width: 240 });
  await prisma.user.update({ where: { id: context.user.id }, data: { twoFactorPendingSecretEncrypted: encryptSecret(secret) } });
  return NextResponse.json({ secret, qrCode });
}

export async function PATCH(request: NextRequest) {
  const context = await getRequestContext();
  if (!context) return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  const parsed = codeSchema.safeParse(await request.json());
  if (!parsed.success || !context.user.twoFactorPendingSecretEncrypted) {
    return NextResponse.json({ error: "Start the two-factor setup again." }, { status: 400 });
  }
  const secret = decryptSecret(context.user.twoFactorPendingSecretEncrypted);
  if (!verifyTotp(parsed.data.code, secret)) return NextResponse.json({ error: "The authentication code is incorrect." }, { status: 400 });
  const recoveryCodes = generateRecoveryCodes();
  await prisma.user.update({
    where: { id: context.user.id },
    data: {
      twoFactorEnabled: true,
      twoFactorSecretEncrypted: encryptSecret(secret),
      twoFactorPendingSecretEncrypted: null,
      twoFactorRecoveryCodeHashes: recoveryCodes.map(hashRecoveryCode),
      authVersion: { increment: 1 },
    },
  });
  return NextResponse.json({ ok: true, recoveryCodes, signedOut: true });
}

export async function PUT(request: NextRequest) {
  const context = await getRequestContext();
  if (!context) return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  const parsed = codeSchema.safeParse(await request.json());
  if (!parsed.success || !context.user.twoFactorEnabled || !context.user.twoFactorSecretEncrypted) {
    return NextResponse.json({ error: "Two-factor authentication is not enabled." }, { status: 400 });
  }
  if (!verifyTotp(parsed.data.code, decryptSecret(context.user.twoFactorSecretEncrypted))) {
    return NextResponse.json({ error: "The authentication code is incorrect." }, { status: 400 });
  }
  const recoveryCodes = generateRecoveryCodes();
  await prisma.user.update({ where: { id: context.user.id }, data: { twoFactorRecoveryCodeHashes: recoveryCodes.map(hashRecoveryCode) } });
  return NextResponse.json({ ok: true, recoveryCodes });
}

export async function DELETE(request: NextRequest) {
  const context = await getRequestContext();
  if (!context) return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  const parsed = codeSchema.safeParse(await request.json());
  if (!parsed.success || !context.user.twoFactorEnabled || !context.user.twoFactorSecretEncrypted) {
    return NextResponse.json({ error: "Two-factor authentication is not enabled." }, { status: 400 });
  }
  if (!verifyTotp(parsed.data.code, decryptSecret(context.user.twoFactorSecretEncrypted))) {
    return NextResponse.json({ error: "The authentication code is incorrect." }, { status: 400 });
  }
  await prisma.user.update({
    where: { id: context.user.id },
    data: {
      twoFactorEnabled: false,
      twoFactorSecretEncrypted: null,
      twoFactorPendingSecretEncrypted: null,
      twoFactorRecoveryCodeHashes: [],
      authVersion: { increment: 1 },
    },
  });
  return NextResponse.json({ ok: true, signedOut: true });
}
