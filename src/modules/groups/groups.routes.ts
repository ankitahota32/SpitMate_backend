import { Router } from "express";
import { z } from "zod";
import { prisma } from "../../lib/prisma";
import { requireAuth, AuthedRequest } from "../../middleware/auth";

export const groupsRouter = Router();
groupsRouter.use(requireAuth);

const createGroupSchema = z.object({ name: z.string().trim().min(1).max(100) });

groupsRouter.post("/", async (req: AuthedRequest, res) => {
    const { name } = createGroupSchema.parse(req.body);

    const group = await prisma.group.create({
        data: {
            name,
            ownerId: req.userId!,
            memberships: { create: { userId: req.userId!, role: "OWNER" } },
        },
    });
    res.status(201).json({ group });
});

groupsRouter.get("/", async (req: AuthedRequest, res) => {
    const memberships = await prisma.membership.findMany({
        where: { userId: req.userId! },
        include: { group: true },
    });

    res.json({
        groups: memberships.map((m) => ({ id: m.group.id, name: m.group.name, role: m.role })),
    });
});