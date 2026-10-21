// Cookie Clicker 2: Evolution Protocol - online trading backend
// Node.js 20+. SQLite-backed accounts, server-side wallets, escrow, and atomic trades.
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const app = express();
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(express.json({ limit: "16kb" }));
app.use(rateLimit({ windowMs: 60_000, limit: 120 }));
const db = new Database(process.env.DB_FILE || "trading.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, cookies INTEGER NOT NULL DEFAULT 0 CHECK(cookies >= 0),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS trades (
 id TEXT PRIMARY KEY, from_id INTEGER NOT NULL REFERENCES users(id),
 to_id INTEGER NOT NULL REFERENCES users(id), offer_cookies INTEGER NOT NULL CHECK(offer_cookies > 0),
 request_cookies INTEGER NOT NULL CHECK(request_cookies >= 0),
 status TEXT NOT NULL CHECK(status IN ('pending','accepted','declined','cancelled')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS trades_to_status ON trades(to_id,status);
`);
const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  console.error("Set JWT_SECRET to a long random secret (at least 32 characters).");
  process.exit(1);
}
const cleanName = v => typeof v === "string" ? v.trim() : "";
function auth(req,res,next){
  const h=req.headers.authorization||"";
  const token=h.startsWith("Bearer ")?h.slice(7):"";
  try { const payload=jwt.verify(token,secret); req.user=db.prepare("SELECT id,username,cookies FROM users WHERE id=?").get(payload.id); if(!req.user) throw Error(); next(); }
  catch { res.status(401).json({error:"Sign in again to continue."}); }
}
app.get("/health",(_req,res)=>res.json({ok:true,service:"CC2 trading backend"}));
app.post("/auth/register", async (req,res)=>{
  const username=cleanName(req.body.username), password=req.body.password;
  if(!/^[A-Za-z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:"Username must be 3–24 letters, numbers, or underscores."});
  if(typeof password!=="string"||password.length<10||password.length>128) return res.status(400).json({error:"Password must be 10–128 characters."});
  try {
    const hash=await bcrypt.hash(password,12);
    const result=db.prepare("INSERT INTO users(username,password_hash,cookies) VALUES(?,?,?)").run(username,hash,10000);
    const token=jwt.sign({id:result.lastInsertRowid},secret,{expiresIn:"7d"});
    res.status(201).json({token});
  } catch(e){ if(String(e).includes("UNIQUE")) return res.status(409).json({error:"That username is already taken."}); res.status(500).json({error:"Could not create account."}); }
});
app.post("/auth/login", async (req,res)=>{
  const username=cleanName(req.body.username), password=req.body.password;
  const user=db.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE").get(username);
  if(!user||typeof password!=="string"||!(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:"Username or password is incorrect."});
  res.json({token:jwt.sign({id:user.id},secret,{expiresIn:"7d"})});
});
app.get("/wallet",auth,(req,res)=>res.json({username:req.user.username,cookies:req.user.cookies}));
app.post("/trades",auth,(req,res)=>{
  const toName=cleanName(req.body.toName), offer=Number(req.body.offerCookies), request=Number(req.body.requestCookies);
  if(!/^[A-Za-z0-9_]{3,24}$/.test(toName)) return res.status(400).json({error:"Enter a valid recipient username."});
  if(!Number.isSafeInteger(offer)||offer<1||!Number.isSafeInteger(request)||request<0) return res.status(400).json({error:"Cookie amounts must be valid whole numbers."});
  const to=db.prepare("SELECT id,username FROM users WHERE username=? COLLATE NOCASE").get(toName);
  if(!to) return res.status(404).json({error:"Recipient account not found. They must create an account first."});
  if(to.id===req.user.id) return res.status(400).json({error:"You cannot trade with yourself."});
  try {
    const create=db.transaction(()=>{
      const sender=db.prepare("SELECT cookies FROM users WHERE id=?").get(req.user.id);
      if(sender.cookies<offer) throw new Error("INSUFFICIENT");
      db.prepare("UPDATE users SET cookies=cookies-? WHERE id=?").run(offer,req.user.id); // escrow
      const id=crypto.randomUUID();
      db.prepare("INSERT INTO trades(id,from_id,to_id,offer_cookies,request_cookies,status) VALUES(?,?,?,?,?,'pending')").run(id,req.user.id,to.id,offer,request);
      return id;
    });
    res.status(201).json({id:create(),status:"pending"});
  } catch(e){if(e.message==="INSUFFICIENT")return res.status(400).json({error:"Not enough cookies in your online wallet."});res.status(500).json({error:"Could not create trade offer."});}
});
app.get("/trades",auth,(req,res)=>{
  const rows=db.prepare(`SELECT t.id, f.username AS fromName, toU.username AS toName, t.offer_cookies AS offerCookies, t.request_cookies AS requestCookies, t.status, t.created_at AS createdAt
    FROM trades t JOIN users f ON f.id=t.from_id JOIN users toU ON toU.id=t.to_id
    WHERE (t.from_id=? OR t.to_id=?) ORDER BY t.created_at DESC LIMIT 100`).all(req.user.id,req.user.id);
  res.json({trades:rows});
});
app.post("/trades/:id/:action",auth,(req,res)=>{
  const action=req.params.action;
  if(!["accept","decline"].includes(action)) return res.status(400).json({error:"Unknown trade action."});
  try {
    const finish=db.transaction(()=>{
      const t=db.prepare("SELECT * FROM trades WHERE id=?").get(req.params.id);
      if(!t||t.to_id!==req.user.id) throw new Error("NOT_FOUND");
      if(t.status!=="pending") throw new Error("NOT_PENDING");
      if(action==="decline"){
        db.prepare("UPDATE users SET cookies=cookies+? WHERE id=?").run(t.offer_cookies,t.from_id);
        db.prepare("UPDATE trades SET status='declined' WHERE id=?").run(t.id);
        return "declined";
      }
      const recipient=db.prepare("SELECT cookies FROM users WHERE id=?").get(t.to_id);
      if(recipient.cookies<t.request_cookies) throw new Error("INSUFFICIENT");
      db.prepare("UPDATE users SET cookies=cookies-? WHERE id=?").run(t.request_cookies,t.to_id);
      db.prepare("UPDATE users SET cookies=cookies+? WHERE id=?").run(t.offer_cookies+t.request_cookies,t.to_id);
      db.prepare("UPDATE users SET cookies=cookies+? WHERE id=?").run(t.request_cookies,t.from_id);
      db.prepare("UPDATE trades SET status='accepted' WHERE id=?").run(t.id);
      return "accepted";
    });
    res.json({status:finish()});
  } catch(e){
    if(e.message==="NOT_FOUND")return res.status(404).json({error:"Pending offer not found for your account."});
    if(e.message==="NOT_PENDING")return res.status(409).json({error:"This offer has already been handled."});
    if(e.message==="INSUFFICIENT")return res.status(400).json({error:"You don't have enough cookies in your online wallet to accept this offer."});
    res.status(500).json({error:"Could not complete trade."});
  }
});
app.post("/trades/:id/cancel",auth,(req,res)=>{
  try {
    const run=db.transaction(()=>{
      const t=db.prepare("SELECT * FROM trades WHERE id=?").get(req.params.id);
      if(!t||t.from_id!==req.user.id)throw new Error("NOT_FOUND");
      if(t.status!=="pending")throw new Error("NOT_PENDING");
      db.prepare("UPDATE users SET cookies=cookies+? WHERE id=?").run(t.offer_cookies,t.from_id);
      db.prepare("UPDATE trades SET status='cancelled' WHERE id=?").run(t.id);
    });run();res.json({status:"cancelled"});
  }catch(e){res.status(e.message==="NOT_FOUND"?404:409).json({error:e.message==="NOT_FOUND"?"Offer not found.":"Offer is no longer pending."});}
});
// Demo starter wallet funding is deliberately NOT exposed as a public endpoint.
// New accounts start with 10,000 online-wallet cookies. Add secure game-earned rewards later.
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`CC2 trading backend listening on port ${port}`));
