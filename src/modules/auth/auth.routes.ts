import { Router } from "express";
import { prisma } from "../../lib/prisma";
import { HttpError } from "../../middleware/errorHandler";
import { requireAuth, AuthedRequest } from "../../middleware/auth";
import { loginSchema, signupSchema } from "./auth.service";
import {
  comparePassword,
  hashPassword,
  issueRefreshToken,
  rotateRefreshToken,
  signAccessToken,
} from "./auth.service";

import type { Response } from "express";

export const authRouter = Router();

const REFRESH_COOKIE = "refreshToken";

function setRefreshCookie(res: Response, token: string) {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/api/auth",
    maxAge: 1000 * 60 * 60 * 24 * 30,
  });
}

authRouter.post("/signup", async (req, res) => {
  const { name, email, password } = signupSchema.parse(req.body);

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing)
    throw new HttpError(409, "An account with this email already exists");

  const passwordHash = await hashPassword(password);
  const user = await prisma.user.create({
    data: { name, email, passwordHash },
  });

  const accessToken = signAccessToken(user.id);
  const refreshToken = await issueRefreshToken(user.id);
  setRefreshCookie(res, refreshToken);

  res.status(201).json({
    user: { id: user.id, name: user.name, email: user.email },
    accessToken,
  });
});

authRouter.post("/login", async (req, res) => {
  const { email, password } = loginSchema.parse(req.body);

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new HttpError(401, "Invalid email or password");

  const valid = await comparePassword(password, user.passwordHash);
  if (!valid) throw new HttpError(401, "Invalid email or password");

  const accessToken = signAccessToken(user.id);
  const refreshToken = await issueRefreshToken(user.id);
  setRefreshCookie(res, refreshToken);

  res.json({
    user: { id: user.id, name: user.name, email: user.email },
    accessToken,
  });
});

authRouter.post("/refresh", async (req, res) => {
  const raw = req.cookies?.[REFRESH_COOKIE];
  if (!raw) throw new HttpError(401, "No refresh token");

  const result = await rotateRefreshToken(raw);
  if (!result) {
    res.clearCookie(REFRESH_COOKIE, { path: "/api/auth" });
    throw new HttpError(401, "Refresh token invalid or expired");
  }

  setRefreshCookie(res, result.newRawToken);
  res.json({ accessToken: signAccessToken(result.userId) });
});

authRouter.get("/me", requireAuth, async (req: AuthedRequest, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.userId! } });
  if (!user) throw new HttpError(401, "User not found");
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
});
