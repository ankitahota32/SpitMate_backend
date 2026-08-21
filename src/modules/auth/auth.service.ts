import bcrypt from "bcryptjs";
import { env } from "../../config/env";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { prisma } from "../../lib/prisma";

const BCRYPT_ROUNDS = 12;

export async function hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, BCRYPT_ROUNDS);
}

export async function comparePassword(password: string, hash: string): Promise<boolean>{
    return bcrypt.compare(password, hash);
}

export interface AccessTokenPayload {
    sub: string;
}

export function signAccessToken(userId: string): string{
    return jwt.sign({ sub: userId } as AccessTokenPayload, env.jwtAccessSecret, {
        expiresIn: env.accessTokenTtl as jwt.SignOptions["expiresIn"],
    });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
    return jwt.verify(token, env.jwtAccessSecret) as AccessTokenPayload;
}

function hashToken(token: string): string {
    return crypto.createHash("sha256").update(token).digest("hex");
}

export async function issueRefreshToken(userId: string): Promise<string> {
    const rawToken = crypto.randomBytes(48).toString("hex");
    const expiresAt = new Date(Date.now() + env.refreshTokenTtlDays * 24 * 60 * 60 * 1000);

    await prisma.refreshToken.create({
        data: { tokenHash: hashToken(rawToken), userId, expiresAt },
    });
    
    return rawToken;
}

export async function rotateRefreshToken(
    rawToken: string
): Promise<{ userId: string; newRawToken: string } | null> {
    const tokenHash = hashToken(rawToken);
    const record = await prisma.refreshToken.findUnique({ where: { tokenHash } });

    if (!record) return null;

    if (record.revoked || record.expiresAt < new Date()) {
        await prisma.refreshToken.updateMany({
            where: { userId: record.userId, revoked: false },
            data: { revoked: true },
        });
        return null;
    }

    await prisma.refreshToken.update({
      where: { id: record.id },
      data: { revoked: true },
    });
    const newRawToken = await issueRefreshToken(record.userId);

    return { userId: record.userId, newRawToken }; 
    
}