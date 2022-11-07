import bcrypt from "bcryptjs";
import { redirect } from "@remix-run/server-runtime";
import { createCookieSessionStorage } from "@remix-run/node";
import { db } from "./db.server";

export async function login({ username, password }) {
  const user = await db.user.findFirst({ where: { username } });
  if (!user) return null;

  const isCorrectPassword = await bcrypt.compare(password, user.passwordHash);
  if (!isCorrectPassword) return null;

  return user;
}

export async function register({ username, password }) {
  const passwordHash = await bcrypt.hash(password, 10);
  const user = await db.user.create({
    data: { username, passwordHash },
  });
  return { id: user.id, username };
}

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) throw new Error("SESSION_SECRET must be set");

const storage = createCookieSessionStorage({
  cookie: {
    name: "RJ_SESSION",
    secrets: [sessionSecret],
    secure: true,
    httpOnly: true,
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 30,
  },
});

export async function createUserSession(userId, redirectTo) {
  const session = await storage.getSession();
  session.set("userId", userId);
  return redirect(redirectTo, {
    headers: {
      "Set-Cookie": await storage.commitSession(session),
    },
  });
}

export async function requireUserId(request) {
  const session = await storage.getSession(request.headers.get("Cookie"));
  const userId = session.get("userId");
  if (!userId || typeof userId !== "string") {
    throw redirect("/login");
  }
  return userId;
}
