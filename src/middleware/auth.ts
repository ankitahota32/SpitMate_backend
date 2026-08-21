import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../modules/auth/auth.service";

export interface AuthedRequest extends Request {
  userId?: string;
}

export function requireAuth(
  req: AuthedRequest,
  res: Response,
  next: NextFunction,
) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer")) {
    return res.status(401).json({ error: "Unauthenticated" });
  }

  const token = header.slice("Bearer ".length);
  try {
    const payload = verifyAccessToken(token);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: "Access token expired or invalid" });
  }
}
