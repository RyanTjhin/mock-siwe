import { SIWEConfig } from "connectkit";
import { error } from "console";
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
    localStorage.setItem("anyape-signed-nonce", res.sig);
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
      statement: "Sign-In With ..",
    }).prepareMessage()
  ),

  verifyMessage: async (
    { message, signature }: { message: string; signature: string },
  ) => {
    const signedNonce = localStorage.getItem("anyape-signed-nonce");
    if (!signedNonce) throw Error("No signed nonce found");
    const response = await fetch(`${supabase.url}/functions/v1/siwe`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${supabase.anonKey}`,
      },
      body: JSON.stringify({ message, signature, hmac: signedNonce }),
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
    const clientJwt = localStorage.getItem(supabase.jwtStorageKey);
    if (!clientJwt) return null;
    const response = await fetch(
      `${supabase.url}/functions/v1/siwe?method=session`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${clientJwt}`, //TODO: CHANGE THIS INTO FETCHED CLIENT JWT
        },
        // credentials: "include",
        credentials: "omit",
      },
    );
    if (!response) throw new Error("No session returned.");
    const res = await response.json();
    console.log("getSession res", res);
    return res;
  },

  signOut: async () => {
    localStorage.removeItem(supabase.jwtStorageKey);
    localStorage.removeItem("anyape-signed-nonce");
    return true;
  },
};
