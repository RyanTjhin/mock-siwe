import { SIWEConfig } from "connectkit";
import { SiweMessage } from "siwe";

export const supabase = {
  anonKey: (
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ??
      (() => {
        throw new Error("Missing `$NEXT_PUBLIC_SUPABASE_ANON_KEY`.");
      })()
  ),
  url: (
    process.env.NEXT_PUBLIC_SUPABASE_URL ??
      (() => {
        throw new Error("Missing `$NEXT_PUBLIC_SUPABASE_URL`.");
      })()
  ),
  jwtStorageKey: "supabase-auth-jwt",
};

export const endpointNames = [
  "login",
  "nonce",
  "session",
  "logout",
] as const;

export const endpoints = Object.fromEntries(endpointNames.map((name) => [
  name,
  `${supabase.url}/functions/v1/siwe?method=${name}`,
]));

export const anonSupaFunc = async (
  name: keyof typeof endpoints,
  args: unknown = {},
) => {
  if (!endpoints[name]) {
    throw new Error(`No endpoint for ${name}.`);
  }

  const response = await fetch(endpoints[name], {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${supabase.anonKey}`,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "*",
    },
    body: JSON.stringify(args),
    credentials: "include",
  });

  if (!response.ok) return { error: response.statusText };

  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (err) {
    null;
  }

  return { response, text, json };
};

export const siweConfig: SIWEConfig = {
  getNonce: async () => {
    const response = await fetch(
      `${supabase.url}/functions/v1/siwe?method=nonce`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${supabase.anonKey}`,
        },
        // credentials: "include",
        credentials: "omit",
      },
    );
    if (!response) throw new Error("No nonce returned.");
    const res = await response.json();
    return res.nonce;
  },

  createMessage: (
    { nonce, address, chainId }: {
      nonce: string;
      address: string;
      chainId: number;
    },
  ) => (
    new SiweMessage({
      version: "1",
      domain: window.location.host,
      uri: window.location.origin,
      address,
      chainId,
      nonce,
      // ASCII assertion to sign. Must not contain `\n`.
      // statement: "Sign-In With Ethereum.",
      statement: "KONTOL.",
    }).prepareMessage()
  ),

  verifyMessage: async (
    { message, signature }: { message: string; signature: string },
  ) => {
    const response = await fetch(`${supabase.url}/functions/v1/siwe`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${supabase.anonKey}`,
      },
      body: JSON.stringify({ message, signature }),
      // credentials: "include",
      credentials: "omit",
    });
    const res = await response.json();
    if (!res) throw new Error("verifyMessage Error");
    if (!res.jwt) throw new Error("No JWT returned.");
    if (!supabase) throw new Error("`supabase` is undefined.");
    localStorage.setItem(supabase.jwtStorageKey, res.jwt);
    return true;
  },

  getSession: async () => {
    const response = await fetch(
      `${supabase.url}/functions/v1/siwe?method=session`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${supabase.anonKey}`, //TODO: CHANGE THIS INTO FETCHED CLIENT JWT
        },
        // credentials: "include",
        credentials: "omit",
      },
    );
    if (!response) throw new Error("No session returned.");
    const res = await response.json();
    return res;
  },

  signOut: async () => {
    const { error } = await anonSupaFunc("logout");
    if (error) throw new Error(error);
    return true;
  },
};
