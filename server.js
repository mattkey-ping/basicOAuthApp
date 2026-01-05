// Simple OIDC app using express and openid-client
import express from "express";
import session from "express-session";
import * as openid from "openid-client";

// --- Log module info safely ---
console.log("openid-client version (declared in package.json):", process.env.npm_package_dependencies_openid_client);
console.log("openid-client exports available:", Object.keys(openid));

const { Issuer, generators } = openid;

const {
    OIDC_BASEURL,
    OIDC_CLIENT_ID,
    SESSION_SECRET,
    APP_URL,
    PORT = 10000,
} = process.env;

if (!OIDC_BASEURL) {
    throw new Error("Missing env var: OIDC_BASEURL");
}

const OIDC_ISSUER = `${OIDC_BASEURL}/as`;
const OIDC_SIGNOFF = `${OIDC_BASEURL}/as/signoff`;


console.log("Startup environment:");
console.log("OIDC_ISSUER:", OIDC_ISSUER);
console.log("OIDC_CLIENT_ID:", OIDC_CLIENT_ID);
console.log("APP_URL:", APP_URL);
console.log("SESSION_SECRET set:", !!SESSION_SECRET);
console.log("PORT:", PORT);

if (!OIDC_ISSUER || !OIDC_CLIENT_ID || !APP_URL) {
    throw new Error("Missing required env vars: OIDC_ISSUER, OIDC_CLIENT_ID, APP_URL");
}

const OIDC_REDIRECT_URI = `${APP_URL}/callback`;
console.log("OIDC_REDIRECT_URI:", OIDC_REDIRECT_URI);

const app = express();
app.set("trust proxy", 1);

app.use(
    session({
        name: "sid",
        secret: SESSION_SECRET || "insecure-default",
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, secure: true, sameSite: "lax" },
    })
);

let cachedClient;
async function getClient() {
    if (cachedClient) return cachedClient;
    console.log("Calling Issuer.discover for:", OIDC_ISSUER);

    if (!Issuer) {
        throw new Error("Issuer is not exported by openid-client. Available exports: " + Object.keys(openid));
    }

    const issuer = await Issuer.discover(OIDC_ISSUER);
    console.log("Discovered issuer metadata keys:", Object.keys(issuer.metadata));

    cachedClient = new issuer.Client({
        client_id: OIDC_CLIENT_ID,
        token_endpoint_auth_method: "none",
        redirect_uris: [OIDC_REDIRECT_URI],
        response_types: ["code"],
    });
    console.log("OIDC client created with metadata:", cachedClient.metadata);

    return cachedClient;
}

function ensureAuth(req, res, next) {

    if (req.session?.id_token) {
        console.log("User authenticated with claims:", req.session.userinfo);
        return next();
    }

    // Allow access if the request originated from /appLogin
    const referer = req.headers.referer || "";
    console.log("Referer header:", referer);
    if (referer.includes("applogin")) {
        console.log("Bypassing OIDC because request came from /appLogin (mock login).");
        return next();
    }

    console.log("User not authenticated, redirecting to /login");
    return res.redirect("/login");
}


app.get("/login", async (req, res, next) => {
    try {
        const client = await getClient();
        const code_verifier = generators.codeVerifier();
        const code_challenge = generators.codeChallenge(code_verifier);
        const state = generators.state();
        const nonce = generators.nonce();

        req.session.code_verifier = code_verifier;
        req.session.state = state;
        req.session.nonce = nonce;

        const authUrl = client.authorizationUrl({
            scope: "openid profile email",
            code_challenge,
            code_challenge_method: "S256",
            state,
            nonce,
        });

        console.log("Redirecting user to:", authUrl);
        res.redirect(authUrl);
    } catch (err) {
        console.error("Login error:", err);
        next(err);
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error("Error destroying session:", err);
        }
        res.clearCookie("sid");
        res.redirect(OIDC_SIGNOFF);
    });
});



app.get("/callback", async (req, res, next) => {
    try {
        console.log("Callback received with query params:", req.query);
        const client = await getClient();
        const params = client.callbackParams(req);

        const tokenSet = await client.callback(OIDC_REDIRECT_URI, params, {
            state: req.session.state,
            nonce: req.session.nonce,
            code_verifier: req.session.code_verifier,
        });

        console.log("TokenSet received:", tokenSet);
        console.log("Claims extracted:", tokenSet.claims());

        req.session.id_token = tokenSet.id_token;
        req.session.access_token = tokenSet.access_token;
        req.session.refresh_token = tokenSet.refresh_token;
        req.session.userinfo = tokenSet.claims();

        res.redirect("/");
    } catch (err) {
        console.error("Callback error:", err);
        next(err);
    }
});



app.get("/", ensureAuth, (req, res) => {
    // Check amr value in id_token claims
    const amr = Array.isArray(req.session?.userinfo?.amr) ? req.session.userinfo.amr : [];
    const showRefresh = !amr.includes('pwd');
    res.type("html").send(`
        <html>
        <head>
            <title>hello world</title>
            <link rel="icon" type="image/x-icon" href="https://www.atb.com/static/img/favicon.ico">
        </head>
        <body>
            <h1 id="greeting">hello world</h1>
            <button id="whoami">Who am I?</button>
            ${showRefresh ? '<button id="refresh">Refresh Token</button>' : ''}
            <button id="logout">Logout</button>
            <script>
                document.getElementById('whoami').onclick = async function() {
                    const resp = await fetch('/whoami');
                    if (resp.ok) {
                        const data = await resp.json();
                        if (data.givenName) {
                            document.getElementById('greeting').textContent = 'hello ' + data.givenName;
                        } else {
                            document.getElementById('greeting').textContent = 'hello (unknown)';
                        }
                    } else {
                        document.getElementById('greeting').textContent = 'hello (error)';
                    }
                };
                ${showRefresh ? `
                document.getElementById('refresh').onclick = async function() {
                    const resp = await fetch('/refresh');
                    if (resp.ok) {
                        const data = await resp.json();
                        if (data.success) {
                            document.getElementById('greeting').textContent = 'Token refreshed!';
                        } else {
                            document.getElementById('greeting').textContent = 'Refresh failed: ' + (data.error || 'unknown');
                        }
                    } else {
                        document.getElementById('greeting').textContent = 'Refresh error';
                    }
                };` : ''}
                document.getElementById('logout').onclick = function() {
                    window.location.href = '/logout';
                };
            </script>
        </body>
        </html>
    `);
});

app.get("/appLogin", (req, res) => {
    const logoUrl = process.env.APP_LOGO_URL || "https://via.placeholder.com/150";

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>App Login</title>
      <style>
        body {
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          font-family: Arial, sans-serif;
          background-color: #f9f9f9;
        }
        .login-container {
          text-align: center;
          background: #fff;
          padding: 2rem;
          border-radius: 12px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
          width: 300px;
        }
        .login-container img {
          max-width: 120px;
          margin-bottom: 1rem;
        }
        .login-container input {
          width: 100%;
          padding: 0.75rem;
          margin: 0.5rem 0;
          border: 1px solid #ccc;
          border-radius: 6px;
        }
        .login-container button {
          width: 100%;
          padding: 0.75rem;
          background: #0072f0;
          color: white;
          border: none;
          border-radius: 6px;
          cursor: pointer;
        }
        .login-container button:hover {
          background: #005bb5;
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <img src="${logoUrl}" alt="Logo" />
        <form method="GET" action="/">
          <input type="text" name="username" placeholder="Username" required />
          <input type="password" name="password" placeholder="Password" required />
          <button type="submit">Log In</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

// Refresh token endpoint
app.get("/refresh", ensureAuth, async (req, res) => {
    try {
        const client = await getClient();
        const refreshToken = req.session.refresh_token;
        if (!refreshToken) return res.status(400).json({ success: false, error: "No refresh token" });
        const tokenSet = await client.refresh(refreshToken);
        req.session.access_token = tokenSet.access_token;
        req.session.id_token = tokenSet.id_token;
        req.session.refresh_token = tokenSet.refresh_token;
        req.session.userinfo = tokenSet.claims();
        res.json({ success: true });
    } catch (err) {
        console.error("/refresh error:", err);
        res.status(500).json({ success: false, error: "Failed to refresh token" });
    }
});

app.get("/whoami", ensureAuth, async (req, res) => {
    try {
        const client = await getClient();
        const accessToken = req.session.access_token;
        if (!accessToken) return res.status(401).json({ error: "No access token" });
        const userinfo = await client.userinfo(accessToken);
        res.json({ givenName: userinfo.given_name });
    } catch (err) {
        console.error("/whoami error:", err);
        res.status(500).json({ error: "Failed to fetch userinfo" });
    }
});

app.use((err, _req, res, _next) => {
    console.error("Unhandled error:", err);
    res.status(500).send("Something went wrong.");
});

app.listen(PORT, () => {
    console.log(`Listening on ${PORT}`);
});
