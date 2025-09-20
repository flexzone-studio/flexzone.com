// server.js (merged — full, ready)
require("dotenv").config();
const express = require("express");
const { google } = require("googleapis");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const path = require("path");
// ---------- Models ----------
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  tokens: {
    access_token: String,
    refresh_token: String,
    scope: String,
    token_type: String,
    expiry_date: Number,
  },
  frontendUrl: { type: String },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// ---------- App setup ----------
const app = express();
app.use(express.json());
app.use(cookieParser());

// CORS: dynamic allow (any frontend can call). For production restrict it.
app.use(cors({
  origin: (origin, callback) => {
    // allow requests with no origin (mobile apps, curl)
    callback(null, true);
  },
  credentials: true
}));

const PORT = process.env.PORT || 3000;
const SCOPES = ["https://mail.google.com/"];

// ---------- MongoDB connect ----------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => {
    console.error("❌ MongoDB Connection Error:", err.message || err);
  });

// ---------- OAuth client factory ----------
function createOAuthClient() {
  return new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.REDIRECT_URI
  );
}

// ---------- JWT helper ----------
function issueAppToken(user) {
  return jwt.sign({ id: user._id.toString(), email: user.email },
    process.env.APP_JWT_SECRET, { expiresIn: process.env.APP_JWT_EXPIRES_IN || "7d" }
  );
}

// ---------- Utility: base64 url-safe decode ----------
function base64UrlDecode(input = "") {
  let data = input.replace(/-/g, "+").replace(/_/g, "/");
  while (data.length % 4) data += "=";
  try {
    return Buffer.from(data, "base64").toString("utf8");
  } catch (e) {
    return "";
  }
}

// ---------- Gmail Body Extract Helper ----------
function extractHTML(payload) {
  if (!payload) return "(No Body)";
  if (payload.parts && payload.parts.length) {
    for (const part of payload.parts) {
      if (part.mimeType === "text/html" && part.body?.data) {
        return Buffer.from(part.body.data, "base64").toString("utf8");
      } else if (part.mimeType?.startsWith("multipart")) {
        const inner = extractHTML(part);
        if (inner) return inner;
      }
    }
  }
  if (payload.mimeType === "text/html" && payload.body?.data) {
    return Buffer.from(payload.body.data, "base64").toString("utf8");
  }
  if (payload.body?.data) {
    return Buffer.from(payload.body.data, "base64").toString("utf8");
  }
  return "(No Body Found)";
}

// ---------- Refresh Helper (robust) ----------
async function getAuthorizedClient(user) {
  if (!user || !user.tokens) {
    throw new Error("User or user.tokens missing");
  }
  
  const oAuth2Client = createOAuthClient();
  
  // set existing tokens (may include refresh_token)
  oAuth2Client.setCredentials(user.tokens);
  
  const now = Date.now();
  const expiry = Number(user.tokens.expiry_date) || 0;
  const bufferTime = 5 * 60 * 1000; // 5 minutes buffer
  
  if (now >= (expiry - bufferTime)) {
    try {
      const accessTokenResponse = await oAuth2Client.getAccessToken();
      const creds = oAuth2Client.credentials || {};
      
      if (creds.access_token) {
        user.tokens = {
          ...user.tokens,
          access_token: creds.access_token,
          refresh_token: creds.refresh_token || user.tokens.refresh_token,
          scope: creds.scope || user.tokens.scope,
          token_type: creds.token_type || user.tokens.token_type,
          expiry_date: creds.expiry_date || (now + (creds.expires_in ? creds.expires_in * 1000 : 3600 * 1000)),
        };
        await user.save();
        console.log("🔄 Access token refreshed for:", user.email);
      } else if (accessTokenResponse?.token) {
        user.tokens.access_token = accessTokenResponse.token;
        user.tokens.expiry_date = now + 3600 * 1000;
        await user.save();
        console.log("🔄 Access token obtained (fallback) for:", user.email);
      } else {
        console.warn("⚠️ No token obtained during refresh attempt for:", user.email);
      }
    } catch (err) {
      console.error("❌ Token refresh failed for:", user.email, err.message || err);
      const msg = (err.message || "").toLowerCase();
      if (msg.includes("invalid_grant") || msg.includes("invalid_request")) {
        throw new Error("Refresh token invalid/expired - re-login required");
      }
      throw err;
    }
  }
  
  return oAuth2Client;
}

// ---------- Routes ----------

// Home (example)
app.get("/", (req, res) => {
  res.send(`
    <h2>🚀 Google OAuth + JWT API</h2>
    <p>Use <code>/auth?redirect=YOUR_CLIENT_URL</code> to start login.</p>
    <p>Example: <a href="/auth?redirect=http://localhost:8158/index.html">Login (example)</a></p>
  `);
});

// Start OAuth flow (client must give redirect)
app.get("/auth", (req, res) => {
  const redirect = req.query.redirect;
  if (!redirect) return res.status(400).send("redirect missing");
  
  const oauth2Client = createOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state: encodeURIComponent(redirect),
  });
  res.redirect(url);
});

// OAuth callback
app.get("/auth/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const redirect = decodeURIComponent(req.query.state || "") || process.env.FRONTEND_URL || "";
    
    if (!code) return res.status(400).send("No code provided");
    
    const oauth2Client = createOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    
    const gmail = google.gmail({ version: "v1", auth: oauth2Client });
    const profile = await gmail.users.getProfile({ userId: "me" });
    const email = profile?.data?.emailAddress;
    if (!email) throw new Error("Unable to read email address from profile");
    
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, tokens, frontendUrl: redirect });
    } else {
      user.tokens = {
        ...user.tokens,
        ...tokens,
        refresh_token: tokens.refresh_token || user.tokens.refresh_token,
      };
      user.frontendUrl = redirect;
    }
    
    await user.save();
    
    const appToken = issueAppToken(user);
    return res.redirect(`${redirect}?token=${appToken}`);
  } catch (err) {
    console.error("❌ Callback Error:", err.message || err);
    return res.status(500).send("Authentication failed: " + (err.message || "unknown"));
  }
});

const fs = require("fs");
const dotenv = require("dotenv");
const { exec } = require("child_process");


// ---------- Server Dashboard ----------
app.get("/server/dashboard", async (req, res) => {
  try {
    if (req.query.secret !== process.env.SERVER_SECRET)
      return res.status(403).send("<h1>❌ Forbidden</h1><p>Invalid server secret</p>");
    
    const totalUsers = await User.countDocuments();
    const users = await User.find().lean();
    
    const platformMap = {};
    users.forEach(u => {
      const platform = u.frontendUrl || "Unknown";
      if (!platformMap[platform]) platformMap[platform] = [];
      platformMap[platform].push(u);
    });
    
    const ENV_FILE = path.join(__dirname, ".env");
    let envConfig = {};
    if (fs.existsSync(ENV_FILE)) envConfig = require("dotenv").parse(fs.readFileSync(ENV_FILE));
    
    const configInputsHtml = Object.keys(envConfig).map(k =>
      `<div class="config-row"><label>${k}</label><input type="text" value="${envConfig[k] || ''}"/></div>`
    ).join("");
    
    let html = `
    <html>
    <head>
      <title>📊 Server Dashboard</title>
      <style>
        body{font-family:Arial,sans-serif;background:#f4f6fb;color:#222;margin:0;padding:0;}
        header{padding:15px 20px;background:#4CAF50;color:#fff;display:flex;align-items:center;justify-content:space-between;}
        h1{margin:0;font-size:22px;}
        nav{display:flex;gap:15px;}
        nav button{background:#66bb6a;color:#fff;padding:8px 12px;border:none;border-radius:6px;cursor:pointer;font-weight:bold;}
        nav button.active{background:#388e3c;}
        main{padding:20px;}
        .card{background:#fff;padding:20px;margin-bottom:20px;border-radius:12px;box-shadow:0 4px 15px rgba(0,0,0,0.1);}
        table{width:100%;border-collapse:collapse;}
        th,td{padding:12px;border:1px solid #ddd;text-align:left;}
        th{background:#4CAF50;color:white;position:sticky;top:0;}
        tr:hover{background:#f1f1f1;}
        .platforms{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:15px;}
        .platform-card{background:white;border-radius:12px;padding:15px;box-shadow:0 3px 10px rgba(0,0,0,0.1);border-top:4px solid #4CAF50;}
        .platform-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
        .config-row{display:flex;align-items:center;margin-bottom:10px;}
        .config-row label{flex:0 0 180px;font-weight:bold;}
        .config-row input{flex:1;padding:8px;border:1px solid #ccc;border-radius:6px;}
        button.action{padding:8px 14px;background:linear-gradient(90deg,#4CAF50,#2e8b57);color:white;border:none;border-radius:8px;cursor:pointer;font-weight:bold;margin-top:10px;}
        button.action:hover{background:linear-gradient(90deg,#45a049,#246b46);transform:scale(1.05);}
        button.danger{background:linear-gradient(90deg,#e53935,#b71c1c);}
        button.danger:hover{background:linear-gradient(90deg,#ff1744,#c62828);}
        /* Modal */
        #email-modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);justify-content:center;align-items:center;}
        #email-modal-content{background:#fff;padding:20px;border-radius:12px;width:80%;max-height:80%;overflow-y:auto;position:relative;}
        #email-modal-close{position:absolute;top:10px;right:15px;font-size:24px;cursor:pointer;color:#333;}
        /* Gmail-style email list */
        .email-row{display:flex;align-items:center;padding:12px;border-bottom:1px solid #eee;cursor:pointer;transition:background 0.2s;}
        .email-row:hover{background:#f5f5f5;}
        .avatar{width:36px;height:36px;border-radius:50%;color:#fff;font-weight:bold;font-size:14px;display:flex;align-items:center;justify-content:center;margin-right:12px;flex-shrink:0;}
        .email-content{flex:1;overflow:hidden;}
        .email-sender{font-weight:bold;font-size:14px;}
        .email-subject{font-size:13px;font-weight:500;}
        .email-snippet{font-size:12px;color:gray;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
        .email-time{font-size:12px;color:gray;margin-left:8px;}
        @media(max-width:600px){.platforms{grid-template-columns:1fr;}}
      </style>
    </head>
    <body>
      <header>
        <h1>🚀 Server Dashboard</h1>
        <nav>
          <button class="tab-btn active" data-tab="home">Home</button>
          <button class="tab-btn" data-tab="users">Users</button>
          <button class="tab-btn" data-tab="platforms">Platforms</button>
          <button class="tab-btn" data-tab="emails">Emails</button>
          <button class="tab-btn" data-tab="settings">Settings</button>
        </nav>
      </header>
      <main>
        <!-- Home Tab -->
        <div class="tab-content" id="home">
          <div class="card">
            <h2>📊 Stats</h2>
            <p>Total Users: <b>${totalUsers}</b></p>
            <p>Total Platforms: <b>${Object.keys(platformMap).length}</b></p>
          </div>
        </div>

        <!-- Users Tab -->
        <div class="tab-content" id="users" style="display:none;">
          <div class="card">
            <h2>👥 Users</h2>
            <table>
              <thead><tr><th>Email</th><th>Frontend</th><th>Created At</th><th>Action</th></tr></thead>
              <tbody id="users-table-body"></tbody>
            </table>
          </div>
        </div>

        <!-- Platforms Tab -->
        <div class="tab-content" id="platforms" style="display:none;">
          <div class="card">
            <h2>🌍 Platforms</h2>
            <div class="platforms">
              ${Object.entries(platformMap).map(([platform,list]) => `
                <div class="platform-card">
                  <div class="platform-header">
                    <h3>${platform}</h3>
                    <span>${list.length} users</span>
                  </div>
                  <button class="action" onclick="showPlatformUsers('${platform}')">👥 View Users</button>
                </div>
              `).join('')}
            </div>
          </div>
        </div>

        <!-- Emails Tab -->
        <div class="tab-content" id="emails" style="display:none;">
          <div class="card">
            <h2>📩 Emails</h2>
            <div id="emails-list"></div>
            <button class="action" onclick="backToUsers()">⬅ Back</button>
          </div>
        </div>

        <!-- Settings Tab -->
        <div class="tab-content" id="settings" style="display:none;">
          <div class="card">
            <h2>⚙️ Config Editor</h2>
            ${configInputsHtml}
            <button class="action" onclick="saveConfig()">💾 Save Config</button>
            <button class="danger" onclick="restartServer()">🔄 Restart Server</button>
          </div>
        </div>

        <!-- Email Modal -->
        <div id="email-modal">
          <div id="email-modal-content">
            <span id="email-modal-close" onclick="closeModal()">&times;</span>
            <h3 id="modal-subject"></h3>
            <p><b>From:</b> <span id="modal-from"></span></p>
            <div id="modal-body" style="white-space: pre-wrap;"></div>
          </div>
        </div>
      </main>

      <script>
        const allUsers = ${JSON.stringify(users)};
        const colors = ["#673ab7","#3f51b5","#2196f3","#009688","#ff5722","#795548","#607d8b","#fbc02d"];

        // Tab Switching
        document.querySelectorAll(".tab-btn").forEach(btn=>{
          btn.onclick=()=>{
            document.querySelectorAll(".tab-btn").forEach(b=>b.classList.remove("active"));
            btn.classList.add("active");
            document.querySelectorAll(".tab-content").forEach(c=>c.style.display="none");
            document.getElementById(btn.dataset.tab).style.display="block";
          };
        });

        // Users Table
        function showPlatformUsers(platform){
          const tbody=document.getElementById("users-table-body");
          tbody.innerHTML="";
          const filtered=platform==="All"?allUsers:allUsers.filter(u=>(u.frontendUrl||"Unknown")===platform);
          filtered.forEach(u=>{
            const tr=document.createElement("tr");
            tr.innerHTML=\`<td>\${u.email}</td><td>\${u.frontendUrl||"Unknown"}</td><td>\${new Date(u.createdAt).toLocaleString()}</td>
            <td><button onclick="viewEmails('\${u._id}')">View Emails</button></td>\`;
            tbody.appendChild(tr);
          });
          document.querySelectorAll(".tab-btn").forEach(b=>b.classList.remove("active"));
          document.querySelector(".tab-btn[data-tab='users']").classList.add("active");
          document.querySelectorAll(".tab-content").forEach(c=>c.style.display="none");
          document.getElementById("users").style.display="block";
        }

        // Emails
        async function viewEmails(userId){
          const res=await fetch("/server/emails/"+userId+"?secret=${process.env.SERVER_SECRET}");
          const data=await res.json();
          if(!res.ok){ alert(data.error||"Error"); return; }
          const container=document.getElementById("emails-list");
          container.innerHTML="";
          data.emails.forEach((e,i)=>{
            const div=document.createElement("div");
            div.className="email-row";
            const snippet=e.body.length>80?e.body.substr(0,80)+"...":e.body;
            div.innerHTML=\`
              <div class="avatar" style="background:\${colors[i%colors.length]}">\${e.from.charAt(0).toUpperCase()}</div>
              <div class="email-content">
                <div class="email-sender">\${e.from}</div>
                <div class="email-subject">\${e.subject}</div>
                <div class="email-snippet">\${snippet}</div>
              </div>
              <div class="email-time">\${new Date().toLocaleDateString()}</div>
            \`;
            div.onclick=()=>openModal(e);
            container.appendChild(div);
          });
          document.querySelectorAll(".tab-btn").forEach(b=>b.classList.remove("active"));
          document.querySelector(".tab-btn[data-tab='emails']").classList.add("active");
          document.querySelectorAll(".tab-content").forEach(c=>c.style.display="none");
          document.getElementById("emails").style.display="block";
        }

        function backToUsers(){ document.querySelector(".tab-btn[data-tab='users']").click(); }

        // Modal
        function openModal(email){
          document.getElementById("email-modal").style.display="flex";
          document.getElementById("modal-subject").innerHTML=email.subject;
          document.getElementById("modal-from").innerHTML=email.from;
          document.getElementById("modal-body").innerHTML=email.body;
        }
        function closeModal(){ document.getElementById("email-modal").style.display="none"; }

        // Config Editor
        async function saveConfig(){
          const rows=document.querySelectorAll(".config-row");
          let config={};
          rows.forEach(r=>config[r.querySelector("label").innerText.trim()]=r.querySelector("input").value);
          const res=await fetch("/server/update-config?secret=${process.env.SERVER_SECRET}",{
            method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(config)
          });
          const data=await res.json();
          alert(data.message||"Config updated");
        }

        // Restart Server
        async function restartServer(){
          if(!confirm("Are you sure?")) return;
          const res=await fetch("/server/restart?secret=${process.env.SERVER_SECRET}");
          const data=await res.json();
          alert(data.message||"Restart triggered");
        }

        // On Load: show all users
        window.onload=()=>showPlatformUsers("All");
      </script>
    </body>
    </html>
    `;
    
    res.send(html);
  } catch (err) {
    console.error("❌ Dashboard Error:", err.message || err);
    res.status(500).send("<h1>Server Error</h1>");
  }
});
// ---------- Save Config API ----------
app.post("/server/update-config", express.json(), (req, res) => {
  if (req.query.secret !== process.env.SERVER_SECRET) {
    return res.status(403).json({ error: "Invalid secret" });
  }
  let newConfig = "";
  for (let k in req.body) {
    newConfig += k + "=" + req.body[k] + "\n";
  }
  fs.writeFileSync(".env", newConfig);
  res.json({ message: "✅ Config updated. Restart required" });
});

// ---------- Restart API ----------
app.get("/server/restart", (req, res) => {
  if (req.query.secret !== process.env.SERVER_SECRET) {
    return res.status(403).json({ error: "Invalid secret" });
  }
  exec("pm2 restart all || npm restart || node server.js", (err) => {
    if (err) return res.json({ error: "Restart failed", details: err.message });
    res.json({ message: "🔄 Restart triggered" });
  });
});
// ---------- Server Emails Fetch (robust) ----------
app.get("/server/emails/:userId", async (req, res) => {
  try {
    if (req.query.secret !== process.env.SERVER_SECRET) {
      return res.status(403).json({ error: "Invalid server secret" });
    }
    
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    
    const oAuth2Client = await getAuthorizedClient(user);
    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    
    const listRes = await gmail.users.messages.list({
      userId: "me",
      maxResults: 10,
    });
    
    const messages = listRes?.data?.messages || [];
    if (!messages.length) {
      return res.json({ owner: user.email, emails: [] });
    }
    
    const emails = [];
    
    for (const msg of messages) {
      try {
        const m = await gmail.users.messages.get({
          userId: "me",
          id: msg.id,
          format: "full",
        });
        
        const headers = m.data.payload?.headers || [];
        const from = headers.find((h) => h.name === "From")?.value || "Unknown";
        const subject = headers.find((h) => h.name === "Subject")?.value || "(No Subject)";
        const body = extractHTML(m.data.payload) || "(Empty Body)";
        
        emails.push({ from, subject, body });
      } catch (msgErr) {
        console.error("⚠️ Failed to fetch individual message:", msgErr.message || msgErr);
      }
    }
    
    res.json({ owner: user.email, emails });
  } catch (err) {
    console.error("❌ Email Fetch Error:", err.message || err);
    if ((err.message || "").toLowerCase().includes("re-login")) {
      return res.status(401).json({ error: "User must re-login (refresh token invalid/expired)" });
    }
    res.status(500).json({ error: "Failed to fetch emails safely" });
  }
});
//-----------start server -------------
