import {
  decodeBase64Url,
  encodeBase64Url,
} from "https://deno.land/std@0.221.0/encoding/base64url.ts";
import { generateNonce, SiweMessage } from "https://esm.sh/siwe@2.1.4";

type JWTPayload = {
  walletAddress: string;
  exp: number;
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // FIXME change these to your accepted domains!
  "Access-Control-Allow-Headers": "*", // FIXME change these to your accepted domains!
};

// JWT Helpers
const jwtSecret = Deno.env.get("JWT_SECRET");
// const jwtSecret = "super-secret-jwt-token-with-at-least-32-characters-long";
const jwtKey = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(jwtSecret),
  { name: "HMAC", hash: "SHA-256" },
  true,
  ["sign", "verify"],
);

async function sign(msg: string) {
  const sig = await crypto.subtle.sign(
    "HMAC",
    jwtKey,
    new TextEncoder().encode(msg),
  );
  return encodeBase64Url(sig);
}

async function jwtSign(payload: JWTPayload) { //TODO: Add types
  const h = encodeBase64Url(
    new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })),
  );
  const p = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const t = `${h}.${p}`;
  const sig = await sign(t);
  return t + "." + encodeBase64Url(sig);
}

async function jwtVerify(jwt: string) {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    console.log("bad length");
    return;
  }
  const sig = await sign(`${parts[0]}.${parts[1]}`);
  if (encodeBase64Url(sig) !== parts[2]) {
    console.log("invalid sig", encodeBase64Url(sig), parts[2]);
    return;
  }
  const pyld = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[1])));
  if (pyld.exp && Date.now() > pyld.exp) {
    console.log("invalid exp");
    return;
  }
  return pyld;
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
      console.log(
        "getNonce Res",
        new Response(
          JSON.stringify({ nonce, sig }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } },
        ),
      );
      return new Response(
        JSON.stringify({ nonce, sig }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    } else if (params.get("method") === "session") {
      const auth = req.headers.get("authorization")?.replace("Bearer ", "");
      console.log("auth", auth);
      if (!auth || auth.length === 0) return unauthorized();
      const jwtPayload = await jwtVerify(auth);

      if (!auth || !jwtPayload) return unauthorized();

      return new Response(
        JSON.stringify({ address: jwtPayload?.walletAddress, chainId: 1 }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    } else {
      return new Response("", { status: 400 });
    }
  }

  if (req.method !== "POST") {
    return new Response("", { status: 405 });
  }
  const { message, signature, hmac } = await req.json();

  // the first verification is the wallet ECDSA signature
  const valid = await new SiweMessage(message).verify({ signature });

  // the second one is against the nonce HMAC we issued earlier
  if (valid.success && await sign(valid.data.nonce) === hmac) {
    const jwt = await jwtSign(
      {
        walletAddress: valid.data.address,
        exp: Date.now() + 60 * 60 * 1000, // validity 1 hour
      },
    );
    return new Response(
      JSON.stringify({ jwt }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  }

  return new Response("ok");
});

// Follow this setup guide to integrate the Deno language server with your editor:
// https://deno.land/manual/getting_started/setup_your_environment
// This enables autocomplete, go to definition, etc.

// console.log("Hello from Functions!")

// Deno.serve(async (req) => {
//   const { name } = await req.json()
//   const data = {
//     message: `Hello ${name}!`,
//   }

//   return new Response(
//     JSON.stringify(data),
//     { headers: { "Content-Type": "application/json" } },
//   )
// })

/* To invoke locally:

  1. Run `supabase start` (see: https://supabase.com/docs/reference/cli/supabase-start)
  2. Make an HTTP request:

  curl -i --location --request POST 'http://127.0.0.1:54321/functions/v1/siwe' \
    --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0' \
    --header 'Content-Type: application/json' \
    --data '{"name":"Functions"}'

*/
