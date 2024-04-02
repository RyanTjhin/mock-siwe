import {
  encodeBase64Url,
} from "https://deno.land/std@0.221.0/encoding/base64url.ts";
import { generateNonce, SiweMessage } from "https://esm.sh/siwe@2.1.4";

import { create, verify } from "https://deno.land/x/djwt@v3.0.2/mod.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // FIXME change these to your accepted domains!
  "Access-Control-Allow-Headers": "*", // FIXME change these to your accepted domains!
};

// JWT Helpers
const jwtSecret = Deno.env.get("JWT_SECRET");

if (!jwtSecret || jwtSecret.length < 32) {
  throw new Error("Invalid JWT secret: Must be at least 32 characters long.");
}

const jwtKey = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(jwtSecret),
  { name: "HMAC", hash: "SHA-256" },
  true,
  ["sign", "verify"],
);

async function sign(msg: string) {
  try {
    const sig = await crypto.subtle.sign(
      "HMAC",
      jwtKey,
      new TextEncoder().encode(msg),
    );
    return encodeBase64Url(sig);
  } catch (error) {
    console.error("Error signing message: ", error);
    throw error;
  }
}

function unauthorized() {
  return new Response("Unauthorized action", { status: 403 });
}
// JWT HELPERS

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method === "GET") {
    const url = new URL(req.url);
    const params = url.searchParams;
    if (params.get("method") === "nonce") {
      const nonce = generateNonce();
      const sig = await sign(nonce);
      return new Response(
        JSON.stringify({ nonce, sig }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    } else if (params.get("method") === "session") {
      const auth = req.headers.get("Authorization")?.replace("Bearer ", "");
      if (!auth || auth.length === 0) return unauthorized();

      const jwtPayload = await verify(auth, jwtKey);
      if (!auth || !jwtPayload) return unauthorized();
      return new Response(
        JSON.stringify({ address: jwtPayload.walletAddress, chainId: 1 }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    } else {
      return new Response("", { status: 400 });
    }
  }

  if (req.method !== "POST") {
    return new Response("", { status: 405 });
  }
  // const { message, signature, hmac } = await req.json();
  const { message, signature, hmac } = await req.json();

  // the first verification is the wallet ECDSA signature
  const valid = await new SiweMessage(message).verify({ signature });

  // the second one is against the nonce HMAC we issued earlier
  if (valid.success && await sign(valid.data.nonce) === hmac) {
    // if (valid.success) {
    const jwt = await create({ alg: "HS256", typ: "JWT" }, {
      walletAddress: valid.data.address,
      exp: Date.now() + 60 * 60 * 1000, // validity 1 hour
    }, jwtKey);
    return new Response(
      JSON.stringify({ jwt }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  }

  return new Response("SHIT POSTING AINT WORKING BRUV");
});
