import { Org, User } from "@prisma/client";

const nodemailer = require("nodemailer");

function publicBaseUrl() {
  const host = process.env.APP_DOMAIN || "localhost:3000";
  return /^https?:\/\//i.test(host) ? host.replace(/\/$/, "") : `${process.env.NODE_ENV === "production" ? "https" : "http"}://${host.replace(/\/$/, "")}`;
}

function mailIdentity(organisation?: Org | null) {
  const companyName = organisation?.name || "BlendSign";
  const configured = organisation?.emailFromAddress || process.env.SMTP_FROM || process.env.SMTP_USER || "no-reply@blendproperty.co.za";
  return {
    from: {
      name: organisation?.emailFromName || companyName,
      address: configured.match(/<([^>]+)>/)?.[1] || configured,
    },
    replyTo: organisation?.email || undefined,
  };
}

export async function sendPasswordResetEmail(user: User, organisation: Org | null, token: string) {
  if (!process.env.SMTP_HOST) throw new Error("SMTP is not configured");
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT || 587) === 465,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } : undefined,
  });
  const resetUrl = `${publicBaseUrl()}/reset-password?token=${encodeURIComponent(token)}`;
  const name = user.firstName || user.name || "there";
  const text = `Hi ${name},\n\nA password reset was requested for your BlendSign account.\n\nReset your password: ${resetUrl}\n\nThis link expires in 30 minutes and can be used once. If you did not request it, you can ignore this email.`;
  const html = `<div style="margin:0;background:#eeeeee;padding:32px;font-family:Arial,sans-serif;color:#191919"><div style="max-width:620px;margin:auto;background:#fff;border:1px solid #d1d1d1;border-radius:16px;overflow:hidden"><div style="padding:24px 28px;border-top:5px solid #e87924"><strong style="font-size:22px">BlendSign</strong></div><div style="padding:12px 28px 34px"><p>Hi ${escapeHtml(name)},</p><h1 style="font-size:24px">Reset your password</h1><p style="line-height:1.6">A password reset was requested for your BlendSign account.</p><p style="margin:28px 0"><a href="${escapeHtml(resetUrl)}" style="display:inline-block;background:#191919;color:#fff;padding:13px 22px;text-decoration:none;border-radius:999px;font-weight:700">Choose a new password</a></p><p style="color:#666;font-size:12px;line-height:1.5">This link expires in 30 minutes and can be used once. If you did not request it, you can ignore this email.</p></div></div></div>`;
  await transporter.sendMail({ ...mailIdentity(organisation), to: user.email, subject: "Reset your BlendSign password", text, html });
}

function escapeHtml(value: string) {
  return String(value).replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[character] || character));
}

