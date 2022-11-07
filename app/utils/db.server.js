import { PrismaClient } from "@prisma/client";

let db = new PrismaClient();
db.$connect();

export { db };
