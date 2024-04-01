export const cors = (origin: string) => {
  const allowedOrigins = [
    /^http:\/\/localhost(:\d+)?/,
    /^https:\/\/code.trwb.live/,
  ];

  const headers = new Headers();
  if (allowedOrigins.some((exp) => exp.test(origin))) {
    headers.set("Access-Control-Allow-Origin", origin);
  }
  headers.set(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  );
  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, *",
  );
  headers.set("Access-Control-Allow-Credentials", "true");

  return headers;
};
