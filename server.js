const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const API_KEY = process.env.REYCLOUD_API_KEY || ''; // keep secret on server only
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'change-this-password';

const DB_FILE = path.join(__dirname, 'data.json');
const sessions = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, key] = String(stored).split(':');
  if (!salt || !key) return false;
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(test), Buffer.from(key));
}
function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    const db = {
      users: [{
        username: ADMIN_USER,
        passwordHash: hashPassword(ADMIN_PASS),
        role: 'Owner', limit: 999, expiry: '2099-12-31'
      }],
      logs: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    return db;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
let db = loadDb();

function publicUser(u) {
  return {username:u.username, role:u.role, limit:u.limit, expiry:u.expiry};
}
function send(res, code, data, type='application/json') {
  res.writeHead(code, {'Content-Type': type, 'Cache-Control':'no-store'});
  res.end(type === 'application/json' ? JSON.stringify(data) : data);
}
function readBody(req) {
  return new Promise((resolve,reject)=>{
    let body='';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) req.destroy();
    });
    req.on('end', ()=> {
      try { resolve(body ? JSON.parse(body) : {}); } catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error',reject);
  });
}
function auth(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  const username = sessions.get(h.slice(7));
  if (!username) return null;
  return db.users.find(u=>u.username===username) || null;
}
function token() {
  return crypto.randomBytes(32).toString('hex');
}

const server = http.createServer(async (req,res)=>{
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/api/health') return send(res,200,{ok:true,server:'central'});

    if (url.pathname === '/api/login' && req.method === 'POST') {
      const body = await readBody(req);
      const u = db.users.find(x=>x.username===String(body.username||'').trim());
      if (!u || !verifyPassword(String(body.password||''), u.passwordHash))
        return send(res,401,{error:'Invalid username or password'});
      const t = token(); sessions.set(t,u.username);
      return send(res,200,{token:t,user:publicUser(u)});
    }

    const user = auth(req);
    if (!user) return send(res,401,{error:'Unauthorized'});

    if (url.pathname === '/api/me' && req.method === 'GET')
      return send(res,200,{user:publicUser(user)});

    if (url.pathname === '/api/users' && req.method === 'GET') {
      if (user.role !== 'Owner') return send(res,403,{error:'Admin only'});
      return send(res,200,{users:db.users.map(publicUser)});
    }

    if (url.pathname === '/api/users' && req.method === 'POST') {
      if (user.role !== 'Owner') return send(res,403,{error:'Admin only'});
      const b = await readBody(req);
      const username = String(b.username||'').trim();
      const password = String(b.password||'');
      if (!username || password.length < 4) return send(res,400,{error:'Username and password are required'});
      if (db.users.some(x=>x.username===username)) return send(res,409,{error:'Username already exists'});
      db.users.push({
        username, passwordHash:hashPassword(password),
        role:String(b.role||'User'), limit:Number(b.limit||100),
        expiry:String(b.expiry||'2099-12-31')
      });
      saveDb(db);
      return send(res,201,{ok:true});
    }

    if (url.pathname.startsWith('/api/users/') && req.method === 'DELETE') {
      if (user.role !== 'Owner') return send(res,403,{error:'Admin only'});
      const username = decodeURIComponent(url.pathname.slice('/api/users/'.length));
      if (username === user.username) return send(res,400,{error:'Cannot delete yourself'});
      const before=db.users.length;
      db.users=db.users.filter(x=>x.username!==username);
      if (db.users.length===before) return send(res,404,{error:'User not found'});
      saveDb(db);
      for (const [t,u] of sessions) if(u===username) sessions.delete(t);
      return send(res,200,{ok:true});
    }

    if (url.pathname === '/api/logs' && req.method === 'GET')
      return send(res,200,{logs:db.logs.slice(-200).reverse()});

    if (url.pathname === '/api/logs' && req.method === 'POST') {
      const b=await readBody(req);
      db.logs.push({
        time:new Date().toISOString(),
        username:user.username,
        target:String(b.target||''),
        payload:String(b.payload||'')
      });
      db.logs=db.logs.slice(-1000);
      saveDb(db);
      return send(res,201,{ok:true});
    }

    if (url.pathname === '/api/provider' && req.method === 'GET') {
      // Never return API_KEY to the browser.
      return send(res,200,{configured:Boolean(API_KEY)});
    }

    if (req.method !== 'GET' && req.method !== 'HEAD')
      return send(res,404,{error:'Not found'});

    let file = url.pathname === '/' ? '/index.html' : url.pathname;
    const filePath = path.join(__dirname, path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
    if (!filePath.startsWith(__dirname)) return send(res,403,{error:'Forbidden'});
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) return send(res,404,{error:'Not found'});
    const ext=path.extname(filePath);
    const types={'.html':'text/html; charset=utf-8','.js':'text/javascript','.css':'text/css','.json':'application/json','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.mp3':'audio/mpeg','.mp4':'video/mp4'};
    res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream'});
    fs.createReadStream(filePath).pipe(res);
  } catch(e) {
    console.error(e);
    send(res,500,{error:'Internal server error'});
  }
});
server.listen(PORT,HOST,()=>console.log(`DIKZ central server running on http://${HOST}:${PORT}`));
