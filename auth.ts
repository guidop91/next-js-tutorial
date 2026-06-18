import bcrypt from "bcrypt";
import Credentials from "next-auth/providers/credentials";
import NextAuth from "next-auth";
import postgres from "postgres";
import z from "zod";
import { authConfig } from "./auth.config";
import type { User } from "@/app/lib/definitions";

const sql = postgres(process.env.POSTGRES_URL!, { ssl: "require" });

const authCredentials = Credentials({
  async authorize(credentials) {
    const parsedCredentials = z
      .object({
        email: z.string().email(),
        password: z.string(),
      })
      .safeParse(credentials);

    if (parsedCredentials.success) {
      const { email, password } = parsedCredentials.data;
      const user = await getUser(email);
      if (!user) return null;

      const passwordsMatch = await bcrypt.compare(password, user.password);
      if (passwordsMatch) return user;
    }
    return null;
  },
});

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [authCredentials],
});

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}
