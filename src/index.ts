import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { env } from "./config/env";
import { errorHandler } from "./middleware/errorHandler";
import { authRouter } from "./modules/auth/auth.routes";
import {groupsRouter} from "./modules/groups/groups.routes"

const app = express();
const port = env.port;

app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.get("/api/health", (req, res) => {
    res.json({ ok: true });
});
app.use("/api/auth", authRouter);

app.use("/api/groups", groupsRouter);

app.use(errorHandler);

app.listen(port, () => {
    console.log(`SplitMate API listening on http://localhost:${port}`);
});
