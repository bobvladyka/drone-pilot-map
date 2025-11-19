require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');
const { Pool } = require('pg');
const path = require('path');
const prerender = require('prerender-node');
const session = require('express-session');
const cors = require('cors'); // Přidejte tento require
const rateLimit = require('express-rate-limit');
const iconv = require('iconv-lite');

const cron = require('node-cron');
const { parsePhoneNumberFromString } = require('libphonenumber-js');

const app = express();

// --- Referral code utils ---
const crypto = require('crypto');
const REF_SECRET = process.env.REF_SECRET || 'super-secret-change-me';

function makeRefCode(userId) {
  const idBase = parseInt(userId, 10).toString(36);        // base36
  const hmac = crypto.createHmac('sha256', REF_SECRET).update(String(userId)).digest('hex');
  const check = hmac.slice(0, 6);                           // 6 znaků stačí
  return `${idBase}-${check}`.toUpperCase();
}



function parseRefCode(code) {
  if (!code || !/^[A-Z0-9]+-[A-F0-9]{6}$/i.test(code)) return null;
  const [idBase, check] = code.split('-');
  const userId = parseInt(idBase, 36);
  if (!Number.isInteger(userId) || userId <= 0) return null;
  const hmac = crypto.createHmac('sha256', REF_SECRET).update(String(userId)).digest('hex');
  const ok = hmac.slice(0, 6).toUpperCase() === check.toUpperCase();
  return ok ? userId : null;
}

// 🧩 Vrátí (a případně vytvoří) referral kód pro přihlášeného pilota
app.get('/ref-code', async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ error: 'Missing email' });

    // 1️⃣ Najdi pilota
    const result = await pool.query('SELECT id, ref_code FROM pilots WHERE email = $1 LIMIT 1', [email]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Pilot not found' });
    }

    let pilot = result.rows[0];
    let code = pilot.ref_code;

    // 2️⃣ Pokud ještě žádný kód nemá → vytvoř a ulož
    if (!code || code.trim() === '') {
      code = makeRefCode(pilot.id); // např. W-02DC37
      await pool.query('UPDATE pilots SET ref_code = $1 WHERE id = $2', [code, pilot.id]);
      console.log(`🔧 Nový referral kód pro ${email}: ${code}`);
    }

    // 3️⃣ Odpověď pro frontend
    res.json({
      code,
      url: `https://najdipilota.cz/register.html?ref=${code}`
    });

  } catch (e) {
    console.error('❌ Chyba v /ref-code:', e);
    res.status(500).json({ error: 'Failed to make or fetch ref code' });
  }
});

// 🧩 ADMIN: doplní ref_code pro všechny piloty, kteří ho zatím nemají
/*
app.get('/admin/fill-refcodes', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, email, ref_code
      FROM pilots
      ORDER BY id ASC
    `);

    let updated = 0;
    for (const pilot of rows) {
      if (!pilot.ref_code || pilot.ref_code.trim() === '') {
        const code = makeRefCode(pilot.id);
        await pool.query('UPDATE pilots SET ref_code = $1 WHERE id = $2', [code, pilot.id]);
        console.log(`💾 ${pilot.email} → ${code}`);
        updated++;
      }
    }

    res.send(`✅ Doplněno ${updated} kódů.`);
  } catch (err) {
    console.error('❌ Chyba při doplňování ref_code:', err);
    res.status(500).send('Chyba při doplňování ref_code');
  }
});
*/


// 🧹 Automatické skrytí e-mailů a telefonních čísel v poznámce
function sanitizeNote(text, defaultCountry = 'CZ') {
  if (!text) return text;

  // Schovej e-maily
  text = text.replace(
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
    '[skryto]'
  );

  // Schovej telefonní čísla (včetně +420, závorek, mezer apod.)
  const tokens = text.split(/(\s+|[.,;:()"\-\/])/);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i].replace(/[^\d+\s().\-]/g, '').trim();
    if (!t) continue;
    const phone = parsePhoneNumberFromString(t, defaultCountry);
    if (phone && phone.isValid && phone.isValid()) {
      tokens[i] = tokens[i].replace(t, '[skryto]');
    }
  }

  // Záchytný fallback – čisté sekvence 7–15 číslic (např. 603947177)
  text = tokens.join('').replace(/\b\d{7,15}\b/g, '[skryto]');

  return text;
}



app.set('trust proxy', true); // pokud běží za proxy (Render/Heroku/Nginx), ať .ip funguje správně

const allowLocalhostOnly = (req, res, next) => {
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = xf || req.ip || req.connection?.remoteAddress || '';
  const allowed = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
  if (allowed.has(ip)) return next();
  return res.status(403).send('Forbidden (admin only on localhost)');
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
    sslmode: 'require'
  }
});

// hned po vytvoření poolu
pool.on('connect', (client) => {
  client.query("SET CLIENT_ENCODING TO 'UTF8'");
  client.query("SET search_path TO public"); // ← DŮLEŽITÉ
});


app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const changePassLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minut
  max: 20
});

const BAD_CHARS = /[ÂÃ ÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞß ]/g;
const GOOD_CZ   = /[ěščřžýáíéůúďťňóĚŠČŘŽÝÁÍÉŮÚĎŤŇÓ]/g;

function scoreCZ(s) {
  return (s.match(GOOD_CZ) || []).length - 2 * (s.match(BAD_CHARS) || []).length;
}

function bestUtfVariant(name) {
  if (typeof name !== 'string') return name;
  const variants = [
    name,
    // simulace „bylo to cestou převedeno do cp1250 a zase mylně čteno jako UTF-8“
    iconv.decode(iconv.encode(name, 'win1250'), 'utf8'),
    // totéž pro latin2
    iconv.decode(iconv.encode(name, 'latin2'), 'utf8'),
  ];
  return variants.reduce((best, cur) => (scoreCZ(cur) > scoreCZ(best) ? cur : best), name);
}

// Session konfigurace
app.use(session({
    secret: process.env.SESSION_SECRET || 'super_tajne_heslo',
    resave: false,
    saveUninitialized: false,
    //cookie: { secure: process.env.NODE_ENV === 'production' } 
    //AKTIVOVAT POKUD ŠOUPU NA SERVER
    cookie: { secure: false } 
   
}));

// Přidejte toto na začátek server.js
app.use(express.json({ type: 'application/json; charset=utf-8' }));

app.use(cors({
  origin: 'https://www.najdipilota.cz', // Povolit pouze vaši doménu
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Povolené HTTP metody
  credentials: true // Povolit cookies a autentizační hlavičky
}));


// Admin route protection middleware
function requireAdminLogin(req, res, next) {
    console.log('isAdmin:', req.session.isAdmin);  // Přidej logování pro session
    if (req.session && req.session.isAdmin) {
        return next();
    }
    return res.redirect('/adminland.html');
}


// TESTOVACÍ struktura MAILU //
app.get('/test-unified-email', async (req, res) => {
  try {
    const html = `
<div style="font-family:'Poppins','Segoe UI',sans-serif;background:#F8F9FA;padding:0;margin:0;">
  <!-- Header -->
  <div style="background:#0077B6;color:#fff;padding:16px 20px;text-align:center;">
    <h1 style="margin:0;font-size:20px;font-weight:600;">NajdiPilota.cz</h1>
  </div>

  <!-- Obsah -->
  <div style="background:#fff;padding:20px;color:#495057;font-size:15px;line-height:1.6;">
    <p>Dobrý den, DrBoom,</p>
    <p>
      Lorem ipsum dolor sit amet, consectetur adipiscing elit.  
      Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
    </p>
    <p>
      Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
    </p>

    <!-- Flat button -->
    <p style="margin:24px 0;">
      <a href="https://www.najdipilota.cz/"
         style="background:#0077B6;color:#fff;text-decoration:none;
                padding:10px 18px;border-radius:6px;font-size:14px;font-weight:500;">
        Otevřít web
      </a>
    </p>
  </div>

  <!-- Footer -->
  <div style="background:#F1F1F1;color:#6c757d;font-size:12px;padding:12px;text-align:center;">
    © 2025 NajdiPilota.cz – Automatická notifikace
  </div>
</div>
    `;

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: 'drboom@seznam.cz',
      subject: 'TEST: Jednotný e-mailový vzhled',
      html
    });

    res.send("✅ Testovací e-mail poslán na drboom@seznam.cz");
  } catch (err) {
    console.error("❌ Chyba v /test-unified-email:", err);
    res.status(500).send("Nepodařilo se odeslat testovací e-mail");
  }
});

function wrapEmailContent(innerHtml, title = "NajdiPilota.cz") {
  return `
<div style="font-family:'Poppins','Segoe UI',sans-serif;background:#F8F9FA;padding:0;margin:0;">
  <!-- Header -->
  <div style="background:#0077B6;color:#fff;padding:16px 20px;text-align:center;">
    <h1 style="margin:0;font-size:20px;font-weight:600;">${title}</h1>
  </div>

  <!-- Content -->
  <div style="background:#fff;padding:20px;color:#495057;font-size:15px;line-height:1.6;">
    ${innerHtml}
  </div>

  <!-- Footer -->
  <div style="background:#F1F1F1;color:#6c757d;font-size:12px;padding:12px;text-align:center;">
    © 2025 NajdiPilota.cz – Automatická notifikace
  </div>
</div>`;
}

// TESTOVACÍ struktura MAILU + Šablona //

/*
app.get("/", (req, res) => {
  res.send("Vše běží!");
});
*/

app.post('/admin-send-custom-email', requireAdminLogin, async (req,res)=>{
  try{
    const { to, subject, body } = req.body;
    if(!to || !subject || !body)
      return res.status(400).send('❌ Chybí příjemce, předmět nebo zpráva.');

    const html = wrapEmailContent(`<p>${escapeHtml(body).replace(/\n/g,'<br>')}</p>`, "NajdiPilota.cz");
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to,
      subject,
      html
    });
    res.send(`✅ E-mail úspěšně odeslán na ${to}`);
  }catch(err){
    console.error('Chyba při odesílání vlastního e-mailu:', err);
    res.status(500).send('❌ Chyba při odesílání e-mailu.');
  }
});




function buildUnreadDigestText(pilotName, items) {
  const lines = items.map(it => (
    `- ${it.advertiserName} <${it.advertiserEmail}> | nepřečtené: ${it.unreadCount}\n  Poslední: ${it.lastMessage}\n  Kdy: ${it.lastTime.toLocaleString('cs-CZ', { timeZone: 'Europe/Prague' })}`
  )).join('\n\n');

  const total = items.reduce((a,b)=>a+b.unreadCount,0);

  return `Dobrý den, ${pilotName},

Máte ${total} nepřečtených zpráv v ${items.length} konverzacích:

${lines}

Přejděte do sekce "Moje zprávy" na https://www.najdipilota.cz/moje-zpravy.html

(Tento přehled chodí jednou denně a neposílá se, pokud nic nepřečteného nemáte.)
`;
}

// bezpečná escapovací utilita pro HTML
function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}



function buildNewDemandsDigestText(pilotName, demands) {
  const lines = demands.map(d => (
    `• ${d.title || 'Bez názvu'} (${d.location || d.region || '—'})` +
    (d.budget != null ? ` — ${d.budget} Kč` : '') +
    `\n  ${(d.description || '').slice(0,150)}${(d.description || '').length > 150 ? '…' : ''}` +
    `\n  Vytvořeno: ${new Date(d.created_at).toLocaleString('cs-CZ', { timeZone: 'Europe/Prague' })}`
  )).join('\n\n');

  return `Dobrý den, ${pilotName || 'pilote'},\n\nNové poptávky:\n\n${lines}\n\nVíce na: https://www.najdipilota.cz/poptavky.html`;
}





// Registrace
app.post('/register', async (req, res) => {
  const {
    name, email, password, phone,
    street, city, zip, region, ref
  } = req.body;
  console.log("🔍 Request body:", req.body);

  // ✅ Normalizace e-mailu
    const normalizedEmail = email.trim().toLowerCase();

  let referrerId = null;
  if (ref) {
    const parsed = parseRefCode(String(ref).trim()); // vrátí userId nebo null
    if (parsed) referrerId = parsed;
  }


   // 🧩 Kontrola, jestli už e-mail existuje (bez ohledu na velikost)
    const existing = await pool.query(
      `SELECT 1 FROM pilots WHERE LOWER(email) = $1 LIMIT 1`,
      [normalizedEmail]
    );
    if (existing.rowCount > 0) {
      console.warn(`⚠️ Pokus o registraci existujícího e-mailu: ${normalizedEmail}`);
      return res.status(400).send("Tento e-mail je již registrován.");
    }

  // Nejprve najdeme nejnižší volné ID
  let nextFreeId;
  try {
    const idResult = await pool.query(`
      WITH sequence AS (
        SELECT generate_series(
          (SELECT MIN(id) FROM pilots),
          (SELECT MAX(id) FROM pilots) + 100  -- +100 jako buffer
        ) AS id
      )
      SELECT MIN(s.id)
      FROM sequence s
      LEFT JOIN pilots p ON s.id = p.id
      WHERE p.id IS NULL
    `);
    
    nextFreeId = idResult.rows[0].min || 1; // Pokud neexistují žádná ID, začneme od 1
    console.log(`Přiřazeno ID: ${nextFreeId}`);
  } catch (err) {
    console.error("Chyba při hledání volného ID:", err);
    return res.status(500).send("Chyba při registraci - nelze přidělit ID");
  }

  const password_hash = await bcrypt.hash(password, 10);
  const location = [street, city, zip, region].filter(Boolean).join(', ');
  let lat = null, lon = null;

  try {
    const response = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(location)}&limit=1`, {
      headers: { 'User-Agent': 'DronMapApp/1.0' }
    });
    const data = await response.json();
    if (data.length > 0) {
      lat = parseFloat(data[0].lat);
      lon = parseFloat(data[0].lon);
    } else {
      console.warn("❗Adresu se nepodařilo geokódovat:", location);
    }

// --- kontrola, zda už v okolí není jiný pilot a případný jemný posun ---
if (lat && lon) {
  try {
    const radiusMeters = 300; // okruh pro kontrolu 300 m
    const earthRadius = 6371000; // poloměr Země v metrech
    const latDelta = (radiusMeters / earthRadius) * (180 / Math.PI);
    const lonDelta = latDelta / Math.cos((lat * Math.PI) / 180);

    const nearby = await pool.query(
      `SELECT id, name, latitude, longitude
       FROM pilots
       WHERE latitude BETWEEN $1 AND $2
         AND longitude BETWEEN $3 AND $4`,
      [lat - latDelta, lat + latDelta, lon - lonDelta, lon + lonDelta]
    );

    if (nearby.rowCount > 0) {
      console.log(
        `⚠️ V okolí (${nearby.rowCount}) pilotů – posouvám nového o náhodnou odchylku.`
      );

      // Posun maximálně o ±0.001° (~100 m)
      const offsetLat = (Math.random() - 0.5) * 0.002; // ±0.001 → cca ±111 m
      const offsetLon = (Math.random() - 0.5) * 0.002; // ±0.001 → cca ±80 m v ČR

      lat = parseFloat((lat + offsetLat).toFixed(6));
      lon = parseFloat((lon + offsetLon).toFixed(6));

      console.log(`📍 Nová posunutá pozice: ${lat}, ${lon}`);
    }
  } catch (err) {
    console.error("❌ Chyba při kontrole blízkých pilotů:", err);
  }
}


  } catch (err) {
    console.error("Chyba při geokódování:", err);
  }

  try {
  let visible_valid = new Date();
console.log("Původní datum: ", visible_valid);
visible_valid.setDate(visible_valid.getDate() + 30);
console.log("Datum po přidání 7 dní: ", visible_valid);


  const insertPilot = await pool.query(
      `INSERT INTO pilots (
        id, name, email, password_hash, phone, street, city, zip, region,
        latitude, longitude, visible_valid, ref_by_email, type_account, available
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING id`,
      [
        nextFreeId, // Explicitně nastavíme ID
        name,
        normalizedEmail, // ✅ uloží se malými písmeny
        password_hash,
        phone,
        street,
        city,
        zip,
        region,
        lat,
        lon,
        visible_valid,
        ref ? String(ref).trim() : null,
        "Basic",
        "ANO"
      ]
    );

  // Pokud referrer existuje, přidáme bonus
// Pokud referrer existuje, přidáme bonus podle ID (bez e-mailu)
if (referrerId) {
  try {
    const refResult = await pool.query(
      `WITH updated_account AS (
         UPDATE pilots
         SET
           type_account = CASE
             WHEN type_account IS NULL OR type_account = 'Free' THEN 'Basic'
             ELSE type_account
           END,
           visible_valid = CASE
             WHEN visible_valid IS NULL THEN (CURRENT_DATE + INTERVAL '7 days')::timestamp
             ELSE visible_valid + INTERVAL '7 days'
           END
         WHERE id = $1
         RETURNING id, email, type_account
       )
       SELECT * FROM updated_account`,
      [referrerId]
    );

    if (refResult.rowCount > 0) {
      const acc = refResult.rows[0].type_account;
      console.log(`🎉 Připsáno +7 dní na ${acc} refererovi id=${referrerId}`);
    }
  } catch (err) {
    console.warn("⚠️ Nepodařilo se připsat bonus refererovi:", err);
  }
}


  const newPilotId = insertPilot.rows[0].id;

  // Hned vložíme výchozí GDPR souhlas
  await pool.query(
    `INSERT INTO consents (
      user_id, consent_type, consent_text, ip_address, user_agent
    ) VALUES ($1, $2, $3, $4, $5)`,
    [
      newPilotId,
      'gdpr_registration',
      'Souhlasím se zpracováním osobních údajů za účelem zobrazení na Platformě NajdiPilota.cz a jejich předání zájemcům o mé služby dle Zásad zpracování osobních údajů.',
      req.ip,
      req.headers['user-agent']
    ]
  );

if (req.body.public_contact === 'on') {
  await pool.query(
    `INSERT INTO consents (user_id, consent_type, consent_text, ip_address, user_agent, timestamp)
     VALUES ($1, 'public_contact', $2, $3, $4, NOW())
     ON CONFLICT (user_id, consent_type)
     DO UPDATE SET timestamp = EXCLUDED.timestamp,
                   consent_text = EXCLUDED.consent_text,
                   ip_address = EXCLUDED.ip_address,
                   user_agent = EXCLUDED.user_agent`,
    [
      newPilotId,
      'Souhlasím se zveřejněním e-mailu a telefonu v mém profilu.',
      req.ip,
      req.headers['user-agent']
    ]
  );
}



  console.log(`✅ Pilot ${name} zaregistrován a GDPR souhlas uložen.`);
      console.log(`✅ Pilot ${name} (${normalizedEmail}) zaregistrován.`);

  
await transporter.sendMail({
  from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
  to: email,
  subject: "Vítejte na NajdiPilota.cz!",
  html: onboardingEmailContent(),
  attachments: [
    {
      filename: "logo.png",
      path: "./icons/logo.png",
      cid: "logoNP"
    }
  ]
});


// Po onboarding mailu novému pilotovi:
const notifyContent = `
  <h2 style="color:#0077B6;">🧑‍✈️ Nový pilot na palubě!</h2>
  <p><strong>Jméno:</strong> ${escapeHtml(name)}</p>
  <p><strong>E-mail:</strong> ${escapeHtml(normalizedEmail)}</p>
  <p><strong>Místo:</strong> ${escapeHtml(city || "")}, ${escapeHtml(region || "")}</p>
`;
await transporter.sendMail({
  from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
  to: "drboom@seznam.cz",
  subject: "🧑‍✈️ Nový pilot na palubě",
  html: wrapEmailContent(notifyContent, "Nový pilot")
});

console.log(`✅ Onboarding e-mail odeslán na: ${email}`);
res.redirect('/'); 

  } catch (err) {
    console.error("Chyba při registraci:", err);
    res.status(500).send("Chyba při registraci");
  }
});


// Přihlášení
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(`SELECT * FROM pilots WHERE email = $1`, [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).send("Uživatel nenalezen.");

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).send("Nesprávné heslo.");

    // Pokud uplynul měsíc, přepneme účet na Free
    let newAccountType = user.type_account;
    const currentDate = new Date();
    if (user.visible_valid && new Date(user.visible_valid) <= currentDate) {
      newAccountType = "Free";  // Po měsíci se přepne na Free
      await pool.query(
        `UPDATE pilots SET type_account = $1 WHERE email = $2`,
        ["Free", email]
      );
      console.log(`Pilot ${email} byl přepnut na typ účtu Free.`);
    }

    // Uložit do session
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.typeAccount = newAccountType;

    res.json({
      success: true,
      id: user.id,
      email: user.email,
      typeAccount: newAccountType
    });

  } catch (err) {
    console.error("Chyba při přihlášení:", err);
    res.status(500).send("Chyba na serveru");
  }
});



// Vrácení všech pilotů
app.get('/pilots', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, name, email, phone, 
        street, city, zip, region,
        latitude, longitude, website,
        note, licenses, drones,
        travel, specialization,
        volunteer, registrationnumber,
        available, visible, visible_payment, visible_valid, type_account
      FROM pilots
      ORDER BY id ASC
    `);

   const pilots = [];
   for (let row of result.rows) {
      // Ověření, jestli má souhlas "public_contact"
      const consentRes = await pool.query(
        'SELECT 1 FROM consents WHERE user_id = $1 AND consent_type = $2 LIMIT 1',
        [row.id, 'public_contact']
      );
      row.hasPublicConsent = consentRes.rowCount > 0;

      // Pokud není souhlas, smažeme z výstupu email a telefon
      if (!row.hasPublicConsent) {
        row.email = null;
        row.phone = null;
      }

      pilots.push(row);
    }

    res.setHeader('Content-Type', 'application/json; charset=utf-8'); // Ensure UTF-8 encoding
    res.json(pilots);
  } catch (err) {
    console.error("Chyba při načítání pilotů:", err);
    res.status(500).json([]);
  }
});

// Reset hesla
const transporter = nodemailer.createTransport({
  host: 'smtp.seznam.cz',
  port: 465,
  secure: true,
  auth: {
    user: 'dronadmin@seznam.cz',
    pass: 'Letamsdrony12'
  }
});

app.post("/change-email", async (req, res) => {
  const { oldEmail, newEmail } = req.body;
  if (!oldEmail || !newEmail) {
    return res.status(400).send("Chybí e-mail.");
  }

  try {
    const result = await pool.query("SELECT id FROM pilots WHERE email = $1", [oldEmail]);
    if (!result.rowCount) {
      return res.status(404).send("Uživatel nenalezen.");
    }

    await pool.query("UPDATE pilots SET email = $1 WHERE email = $2", [newEmail, oldEmail]);

    // Odeslání potvrzovacího e-mailu na původní adresu
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: oldEmail,
      subject: "Změna e-mailové adresy",
      html: buildChangeEmailEmail(oldEmail, newEmail)
    });

    res.send("✅ E-mail byl úspěšně změněn.");
  } catch (err) {
    console.error("Chyba při změně e-mailu:", err);
    res.status(500).send("Chyba při změně e-mailu.");
  }
});


app.post('/reset-password', async (req, res) => {
  let { email } = req.body;
  if (!email) return res.status(400).send("E-mail je povinný.");

  // ✅ Normalizace e-mailu
  email = email.trim().toLowerCase();

   try {
    // ✅ Vyhledávání bez ohledu na velikost písmen
    const result = await pool.query(
      `SELECT * FROM pilots WHERE LOWER(email) = $1`,
      [email]
    );
    const user = result.rows[0];
    if (!user) return res.status(404).send("Uživatel s tímto e-mailem nebyl nalezen.");

    const newPassword = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(newPassword, 10);

    // ✅ Update podle normalizované adresy
    await pool.query(
      `UPDATE pilots SET password_hash = $1 WHERE LOWER(email) = $2`,
      [hash, email]
    );

    await transporter.sendMail({
      from: '"Dronová mapa" <dronadmin@seznam.cz>',
      to: user.email,
      subject: "Nové heslo k účtu",
      text: `Vaše nové heslo je: ${newPassword}\n\nDoporučujeme jej po přihlášení ihned změnit.`
    });

    res.send("Nové heslo bylo odesláno na váš e-mail.");
  } catch (err) {
    console.error("Chyba při resetování hesla:", err);
    res.status(500).send("Chyba na serveru při změně hesla");
  }
});

async function geocodeLocation({ street, city, zip, region }) {
  const queries = [];

  if (street && city && zip && region) queries.push([street, city, zip, region].join(", "));
  if (street && city && zip) queries.push([street, city, zip].join(", "));
  if (street && city) queries.push([street, city].join(", "));
  if (city && zip) queries.push([city, zip].join(", "));
  if (city) queries.push(city);
  if (zip) queries.push(zip);

  for (const q of queries) {
    try {
      const res = await fetch(
        `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(q)}&limit=1`,
        { headers: { "User-Agent": "DronMapApp/1.0" } }
      );
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        return {
          lat: parseFloat(data[0].lat),
          lon: parseFloat(data[0].lon),
          usedQuery: q
        };
      }
    } catch (err) {
      console.error("❌ Chyba při geokódování dotazu:", q, err);
    }
  }

  return { lat: null, lon: null, usedQuery: null };
}

app.post("/update", async (req, res) => {
  console.log("Přijatá data:", req.body);

  let {
    email,
    name,
    phone,
    website,
    street,
    city,
    zip,
    region,
    drones,
    note,
    travel,
    licenses,
    specialization_ids,   // << sem jde pole ID (Array) nebo comma-string
    volunteer,
    registrationnumber,
    available,
    visible,
    visible_payment,
    visible_valid
  } = req.body;

// 🧹 Očisti poznámku (schovej kontaktní údaje)
if (note) {
  note = sanitizeNote(note, 'CZ');
}

    // natáhni stará data (kvůli omezením a defaultům)
const oldDataResult = await pool.query(
  `SELECT visible, visible_valid, visible_payment, type_account, 
          available AS old_available, latitude, longitude,
          street AS old_street, city AS old_city, zip AS old_zip, region AS old_region
   FROM pilots 
   WHERE email = $1`,
  [email]
);
const oldPilotData = oldDataResult.rows[0];

  if (!oldPilotData) {
    return res.status(404).send("Pilot nenalezen.");
  }

  // Převod specialization_ids -> čisté pole čísel
  let specIds = [];
  if (Array.isArray(specialization_ids)) {
    specIds = specialization_ids
      .map(x => Number(x))
      .filter(x => Number.isInteger(x) && x > 0);
  } else if (typeof specialization_ids === "string" && specialization_ids.trim() !== "") {
    specIds = specialization_ids
      .split(",")
      .map(s => Number(s.trim()))
      .filter(x => Number.isInteger(x) && x > 0);
  }

  // 🔒 Restrikce podle typu účtu
  if (oldPilotData.type_account === "Free") {
    available = "ANO";         // vždy ANO
    website = null;            // zakázat
    note = null;               // zakázat
    registrationnumber = null; // zakázat
    visible = "ANO";

    // Free: max 1 specializace
    if (specIds.length > 1) specIds = specIds.slice(0, 1);

    // Free: jen první dron
    if (drones) {
      drones = drones.split(",")[0]?.trim() || null;
    }
  }

  if (oldPilotData.type_account === "Basic") {
    if (!available) available = oldPilotData.old_available;
    // Basic: max 2 specializace (držíme se FE, kde hlídáš 2)
    if (specIds.length > 2) specIds = specIds.slice(0, 2);
    // Basic: max 2 drony
    if (drones) {
      drones = drones
        .split(",")
        .slice(0, 2)
        .map(s => s.trim())
        .filter(Boolean)
        .join(", ") || null;
    }
if (oldPilotData.type_account === "Premium") {
  // Premium: max 10 specializací
  if (specIds.length > 10) specIds = specIds.slice(0, 10);
}

  }

  // 🛡️ available vždy jen ANO/NE
  if (available !== "ANO" && available !== "NE") {
    available = "NE";
  }

  // visible -> ANO/NE
  if (visible === undefined || visible === null) {
    visible = oldPilotData.visible;
  } else {
    visible = visible ? "ANO" : "NE";
  }
  if (!visible_valid)   visible_valid   = oldPilotData.visible_valid;
  if (!visible_payment) visible_payment = oldPilotData.visible_payment;

  // Geokódování s fallbackem
let { lat, lon, usedQuery } = await geocodeLocation({ street, city, zip, region });

// Pokud nic, nech staré souřadnice
if (!lat || !lon) {
  console.warn("❗Nepodařilo se geokódovat adresu, ponechávám staré souřadnice.");
  lat = oldPilotData.latitude;
  lon = oldPilotData.longitude;
} else {
  console.log(`✅ Geokódováno na (${lat}, ${lon}) pomocí dotazu: ${usedQuery}`);
}

// --- kontrola blízkých pilotů při UPDATE a jemný posun ---
if (lat && lon) {
  try {
    const radiusMeters = 300; // okruh pro kontrolu 300 m
    const earthRadius = 6371000; // poloměr Země v metrech
    const latDelta = (radiusMeters / earthRadius) * (180 / Math.PI);
    const lonDelta = latDelta / Math.cos((lat * Math.PI) / 180);

    const nearby = await pool.query(
      `SELECT id, name, latitude, longitude
       FROM pilots
       WHERE latitude BETWEEN $1 AND $2
         AND longitude BETWEEN $3 AND $4
         AND email <> $5`, // vyloučíme právě upravovaného pilota
      [lat - latDelta, lat + latDelta, lon - lonDelta, lon + lonDelta, email]
    );

    if (nearby.rowCount > 0) {
      console.log(
        `⚠️ UPDATE: V okolí (${nearby.rowCount}) pilotů – posouvám o náhodnou odchylku.`
      );

      // Posun maximálně o ±0.001° (~100 m)
      const offsetLat = (Math.random() - 0.5) * 0.002;
      const offsetLon = (Math.random() - 0.5) * 0.002;

      lat = parseFloat((lat + offsetLat).toFixed(6));
      lon = parseFloat((lon + offsetLon).toFixed(6));

      console.log(`📍 UPDATE: Nová posunutá pozice: ${lat}, ${lon}`);
    }
  } catch (err) {
    console.error("❌ Chyba při kontrole blízkých pilotů při UPDATE:", err);
  }
}


  // LOG pro kontrolu
  console.log("Hodnoty pro update:", {
    name, phone, website, street, city, zip, region,
    drones, note, travel, licenses,
    specialization_ids: specIds,
    volunteer, lat, lon, registrationnumber, available, visible
  });

  // Uložení v transakci
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // 1) Update pilots (bez textového 'specialization' – doplníme hezké CSV až po vložení ID)
    const r = await client.query(
      `UPDATE pilots SET 
        name = $1, 
        phone = $2, 
        website = $3, 
        street = $4, 
        city = $5, 
        zip = $6, 
        region = $7,
        drones = $8, 
        note = $9, 
        travel = $10, 
        licenses = $11, 
        volunteer = $12, 
        latitude = $13, 
        longitude = $14,
        registrationnumber = $15,
        available = $16,
        visible = $17,
        visible_payment = $18,
        visible_valid = $19
      WHERE email = $20
      RETURNING id`,
      [
        name || null,
        phone || null,
        website || null,
        street || null,
        city || null,
        zip || null,
        region || null,
        drones || null,
        note || null,
        travel || null,
        licenses || null,
        volunteer === "ANO" ? "ANO" : "NE",
        lat,
        lon,
        registrationnumber || null,
        available,
        visible,
        visible_payment || null,
        visible_valid || null,
        email
      ]
    );

    if (r.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Pilot nenalezen.");
    }
    const pilotId = r.rows[0].id;

    // 2) Přepiš specializace podle ID
    await client.query("DELETE FROM pilot_specializations WHERE pilot_id = $1", [pilotId]);

    if (specIds.length > 0) {
      const values = specIds.map((_, i) => `($1, $${i + 2})`).join(",");
      await client.query(
        `INSERT INTO pilot_specializations (pilot_id, category_id) VALUES ${values}
         ON CONFLICT DO NOTHING`,
        [pilotId, ...specIds]
      );

      // hezké CSV názvů do pilots.specialization pro kompatibilitu
      const csvRes = await client.query(
        `SELECT string_agg(DISTINCT c.name, ', ' ORDER BY c.name) AS csv
         FROM categories c
         WHERE c.id = ANY($1::int[])`,
        [specIds]
      );
      const csv = csvRes.rows[0].csv || null;
      await client.query("UPDATE pilots SET specialization = $1 WHERE id = $2", [csv, pilotId]);
    } else {
      // bez specializací -> nuluj textovou verzi
      await client.query("UPDATE pilots SET specialization = NULL WHERE id = $1", [pilotId]);
    }

    await client.query("COMMIT");
    res.send("✅ Údaje byly úspěšně aktualizovány.");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ ÚPLNÁ CHYBOVÁ ZPRÁVA:", err);
    console.error("❌ STACK TRACE:", err.stack);
    res.status(500).json({
      error: "Chyba při aktualizaci",
      details: err.message,
      stack: process.env.NODE_ENV === "development" ? err.stack : undefined
    });
  } finally {
    client.release();
  }
});

app.post('/add-category', async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "Missing name" });

    // 1️⃣ Urči ID ručně (od 1000 nahoru)
    const idResult = await pool.query(`
      SELECT COALESCE(MAX(id), 999) + 1 AS next_id
      FROM categories
      WHERE id >= 1000
    `);
    const nextId = idResult.rows[0].next_id;

    // 2️⃣ Vytvoř kategorii s ručně přiřazeným ID
    const q = await pool.query(
      `INSERT INTO categories (id, name)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING
       RETURNING id, name`,
      [nextId, name.trim()]
    );

    if (q.rowCount === 0) {
      return res.status(409).json({ error: "Category already exists" });
    }

    res.json(q.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// =======================================================
// DELETE: Kompletní smazání účtu pilota + potvrzovací e-mail
// =======================================================
app.delete("/delete-my-account", async (req, res) => {
  const client = await pool.connect();

  try {
    const { email } = req.body;
    if (!email) return res.status(400).send("Chybí e-mail.");

    const lower = email.toLowerCase();

    await client.query("BEGIN");

    // 1) Najdi pilota (včetně jména pro e-mail)
    const pilotRes = await client.query(
      "SELECT id, name FROM pilots WHERE LOWER(email) = $1",
      [lower]
    );

    if (pilotRes.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).send("Pilot nenalezen.");
    }

    const pilotId = pilotRes.rows[0].id;
    const pilotName = pilotRes.rows[0].name || "";

    // 2) Najdi všechny konverzace pilota
    const convRes = await client.query(
      "SELECT id FROM conversations WHERE pilot_id = $1",
      [pilotId]
    );
    const conversationIds = convRes.rows.map(r => r.id);

    if (conversationIds.length > 0) {

      // 3) Smazat zprávy v konverzacích
      await client.query(
        `DELETE FROM messages 
         WHERE conversation_id = ANY($1::int[])`,
        [conversationIds]
      );

      // 4) Smazat conversation_views
      await client.query(
        `DELETE FROM conversation_views 
         WHERE conversation_id = ANY($1::int[])`,
        [conversationIds]
      );

      // 5) Smazat samotné konverzace
      await client.query(
        `DELETE FROM conversations 
         WHERE id = ANY($1::int[])`,
        [conversationIds]
      );
    }

    // 6) Smazat consents
    await client.query(
      "DELETE FROM consents WHERE user_id = $1",
      [pilotId]
    );

    // 7) Nakonec smazat pilota
    await client.query(
      "DELETE FROM pilots WHERE id = $1",
      [pilotId]
    );

    await client.query("COMMIT");

    // ----------------------------------------------------------
    // ✉️ ODESLAT POTVRZOVACÍ E-MAIL O SMAZÁNÍ ÚČTU (po úspěšném COMMITu)
    // ----------------------------------------------------------
    try {
      await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: email,
        bcc: 'drboom@seznam.cz',
        subject: "Potvrzení o smazání účtu",
        html: deleteAccountEmailContent(pilotName),
        attachments: [
          {
            filename: "logo.png",
            path: "./icons/logo.png",
            cid: "logoNP"
          }
        ]
      });

      console.log("📨 E-mail o smazání účtu odeslán:", email);
    } catch (mailErr) {
      console.error("❌ Nepodařilo se odeslat e-mail o smazání účtu:", mailErr);
    }

    res.send("Účet byl úspěšně smazán.");

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Chyba při mazání účtu:", err);
    res.status(500).send("Chyba při mazání účtu.");
  } finally {
    client.release();
  }
});






app.post('/delete-all', allowLocalhostOnly, requireAdminLogin, async (req, res) => {
  try {
    await pool.query('DELETE FROM pilots');
    res.send("✅ Všechny záznamy byly smazány.");
  } catch (err) {
    console.error("❌ Chyba při mazání:", err);
    res.status(500).send("Chyba při mazání.");
  }
});

app.post('/delete-selected', allowLocalhostOnly,  requireAdminLogin, async (req, res) => {
  const ids = req.body.ids;
  if (!Array.isArray(ids)) {
    return res.status(400).send('Neplatný vstup – očekává se pole ID.');
  }

  try {
    const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
    const query = `DELETE FROM pilots WHERE id IN (${placeholders})`;
    await pool.query(query, ids);
    res.send(`✅ Smazáno ${ids.length} pilotů.`);
  } catch (err) {
    console.error("❌ Chyba při mazání:", err);
    res.status(500).send("Chyba při mazání.");
  }
});


app.post("/inzerent-register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // Ověření shody hesel
  if (password !== confirmPassword) {
    return res.status(400).send("Hesla se neshodují.");
  }

  try {
    const existing = await pool.query("SELECT * FROM advertisers WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(400).send("Tento e-mail už je registrován.");
    }

    // Zahashuj heslo
    const hashedPassword = await bcrypt.hash(password, 10);
	console.log("Registrace probíhá s:", name, email, hashedPassword);
    // Ulož inzerenta do databáze
   const result = await pool.query(
  "INSERT INTO advertisers (name, email, password) VALUES ($1, $2, $3) RETURNING *",
  [name, email, hashedPassword]
);
console.log("Vloženo do DB:", result.rows[0]);

const notifyContent = `
  <h2 style="color:#0077B6;">📢 Nový inzerent se registroval!</h2>
  <p><strong>Jméno / firma:</strong> ${escapeHtml(name)}</p>
  <p><strong>E-mail:</strong> ${escapeHtml(email)}</p>
`;
await transporter.sendMail({
  from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
  to: "drboom@seznam.cz",
  subject: "📢 Nový inzerent na NajdiPilota.cz",
  html: wrapEmailContent(notifyContent, "Nový inzerent")
});
console.log("📧 Notifikace o novém inzerentovi odeslána adminovi");

console.log("Záznam uložen do databáze.");


    res.status(201).send("Registrace úspěšná!");
  } catch (err) {
    console.error("Chyba při registraci:", err);
    res.status(500).send("Nastala chyba při registraci.");
  }
});

// GET /api/v2/advertisers/:uid
app.get('/api/v2/advertisers/:uid', async (req, res) => {
  const { uid } = req.params;
  const sql = `
    SELECT id, uid, name, email, credit_balance, created_at
    FROM advertisers
    WHERE uid = $1
  `;
  const r = await pool.query(sql, [uid]);
  if (!r.rowCount) return res.status(404).json({ error: 'Not found' });
  res.json(r.rows[0]);
});


app.post("/inzerent", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM advertisers WHERE email = $1", [email]);
    const advertiser = result.rows[0];

    if (!advertiser) {
      return res.status(401).json({ success: false, message: "Neplatný e-mail nebo heslo." });
    }

    const match = await bcrypt.compare(password, advertiser.password);
    if (!match) {
  return res.status(401).json({ success: false, message: "Neplatný e-mail nebo heslo." });
}

// >>> PŘIDEJ TOTO:
req.session.userId = advertiser.id;     // volitelné, ale hodí se
req.session.email  = advertiser.email;  // důležité – čte se v /get-my-advertiser a /poptavky
req.session.role   = 'advertiser';

return res.json({             // ✅ tady
      success: true,
      id: advertiser.id,
      uid: advertiser.uid,
      email: advertiser.email
    });

// po ověření hesla:
res.json({
  success: true,
  id: advertiser.id,
  uid: advertiser.uid,      // ← NOVĚ
  email: advertiser.email
});


    res.json({ success: true, message: "Přihlášení proběhlo úspěšně." });
  } catch (error) {
    console.error("Chyba při přihlašování inzerenta:", error);
    res.status(500).json({ success: false, message: "Chyba serveru." });
  }
});

app.post('/inzerent-reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("E-mail je povinný.");

  try {
    const result = await pool.query(`SELECT * FROM advertisers WHERE email = $1`, [email]);
    const user = result.rows[0];
    if (!user) return res.status(404).send("Uživatel s tímto e-mailem nebyl nalezen.");

    const newPassword = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(newPassword, 10);

    await pool.query(`UPDATE advertisers SET password = $1 WHERE email = $2`, [hash, email]);

    await transporter.sendMail({
      from: '"Dronová mapa - Inzerent" <dronadmin@seznam.cz>',
      to: email,
      subject: "Nové heslo k účtu",
      text: `Vaše nové heslo je: ${newPassword}\n\nDoporučujeme jej po přihlášení ihned změnit.`
    });

    res.send("Nové heslo bylo odesláno na váš e-mail.");
  } catch (err) {
    console.error("Chyba při resetování hesla:", err);
    res.status(500).send("Chyba na serveru při změně hesla");
  }
});



app.get('/adminland.html', allowLocalhostOnly, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'adminland.html'));
});

// ADMIN stránka
app.get('/admin.html', allowLocalhostOnly, requireAdminLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'admin.html'));
});


// 📊 STATISTIKY PILOTŮ (včetně referral přehledu)
app.get('/api/statistics', async (req, res) => {
  try {
    const [typeAccounts, regions, specializations, volunteers, totalVisible, referrers] = await Promise.all([
      pool.query(`
        SELECT type_account, COUNT(*) AS count
        FROM pilots
        WHERE visible = 'ANO'
        GROUP BY type_account
        ORDER BY count DESC
      `),
      pool.query(`
        SELECT region, COUNT(*) AS count
        FROM pilots
        WHERE visible = 'ANO'
          AND region IS NOT NULL
          AND region <> ''
        GROUP BY region
        ORDER BY count DESC
      `),
      pool.query(`
        SELECT TRIM(UNNEST(string_to_array(specialization, ','))) AS specialization_name,
               COUNT(*) AS count
        FROM pilots
        WHERE visible = 'ANO'
          AND specialization IS NOT NULL
          AND specialization <> ''
        GROUP BY specialization_name
        ORDER BY count DESC
        LIMIT 10
      `),
      pool.query(`SELECT COUNT(*) AS volunteers FROM pilots WHERE visible = 'ANO' AND volunteer = 'ANO'`),
      pool.query(`SELECT COUNT(*) AS total FROM pilots WHERE visible = 'ANO'`),

      // 🧩 nový dotaz – TOP 5 pilotů, kteří přivedli nové uživatele
      pool.query(`
        SELECT
          p.id,
          p.name,
          p.email,
          p.ref_code,
          COUNT(invited.id) AS invited_count
        FROM pilots invited
        JOIN pilots p ON invited.ref_by_email = p.ref_code
        GROUP BY p.id, p.name, p.email, p.ref_code
        ORDER BY invited_count DESC
        LIMIT 5
      `)
    ]);

    res.json({
      type_accounts: typeAccounts.rows,
      regions: regions.rows,
      specializations: specializations.rows,
      volunteers: volunteers.rows[0].volunteers,
      total_visible: totalVisible.rows[0].total,
      top_referrers: referrers.rows
    });
  } catch (err) {
    console.error("❌ Chyba při načítání statistik:", err);
    res.status(500).json({ error: "Chyba při načítání statistik" });
  }
});

// ---------------------------------------------------------------------
// 💸 NOVÝ ENDPOINT: Sponzorství 7 dní Basic účtu (s kontrolou KREDITU)
// ---------------------------------------------------------------------
app.post('/api/sponsor-upgrade', async (req, res) => {
  const { pilotId, sponsorEmail, days, type, amount } = req.body;

  // Převod 'days' na číslo a kontrola platných hodnot (např. 3, 7, 30...)
  const daysNum = parseInt(days, 10);
  const isValidDays = daysNum > 0 && daysNum <= 365; // Povolíme cokoli do 1 roku 
  
  if (!pilotId || !sponsorEmail || !isValidDays || type !== 'Basic' || !amount) {
    return res.status(400).json({ success: false, message: 'Neplatné parametry sponzorství.' });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN"); // START TRANSACTION

    // 1) Získání a kontrola zůstatku kreditu Inzerenta
    const advRes = await client.query(
      'SELECT id, credit_balance FROM advertisers WHERE email = $1 FOR UPDATE', // ZAMKNUTÍ řádku
      [sponsorEmail]
    );
    if (advRes.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, message: 'Inzerent nenalezen.' });
    }
    const advertiserId = advRes.rows[0].id;
    const currentCredit = parseFloat(advRes.rows[0].credit_balance);
    const cost = parseFloat(amount); // Zde je cena sponzorství (např. 100)

    if (currentCredit < cost) {
      await client.query("ROLLBACK");
      return res.status(403).json({ success: false, message: 'Nedostatečný kredit pro sponzorství.' });
    }

    // 2) ODČTENÍ KREDITU
    await client.query(
      'UPDATE advertisers SET credit_balance = credit_balance - $1 WHERE id = $2',
      [cost, advertiserId]
    );

    // 3) Aktualizace visible_valid pilota
    const updatePilot = await client.query(
      `UPDATE pilots 
       SET 
         type_account = $1,
         visible_valid = COALESCE(visible_valid, CURRENT_DATE) + INTERVAL '${daysNum} days'
       WHERE id = $2
       RETURNING id, email, name, type_account, visible_valid`,
      [type, pilotId]
    );

    if (updatePilot.rowCount === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ success: false, message: 'Pilot nenalezen.' });
    }
    const pilot = updatePilot.rows[0];

    // 4) Zaznamenání sponzorské platby (log)
    await client.query(
      `INSERT INTO sponsorship_logs (pilot_id, sponsor_email, days_added, amount)
       VALUES ($1, $2, $3, $4)`,
      [pilotId, sponsorEmail, daysNum, cost]
    );

    await client.query("COMMIT"); // END TRANSACTION

    // 5) E-mailová notifikace pilotovi o daru (stejná jako předtím)
    // ... (zde ponechte kód pro odeslání notifikačního emailu pilotovi) ...
    await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: pilot.email,
        bcc: 'drboom@seznam.cz',
        subject: `🎁 Gratulujeme! Máte darovaných ${daysNum} dní Basic účtu!`, // days -> daysNum
        html: wrapEmailContent(`
            <p>Dobrý den ${escapeHtml(pilot.name || '')},</p>
            <p>Díky zájemci o Vaše služby (inzerent: <strong>${escapeHtml(sponsorEmail)}</strong>) Vám bylo <strong>darováno ${daysNum} dní</strong> Basic účtu!</p> // days -> daysNum
            <p>Váš účet byl automaticky přepnut na <strong>Basic</strong>, což Vám umožní ihned komunikovat se sponzorem a zviditelnit se pro další zakázky.</p>
            <p>Nová platnost končí: <strong>${new Date(pilot.visible_valid).toLocaleDateString("cs-CZ")}</strong></p>
            <p>Odpovězte sponzorovi co nejdříve!</p>
            <p style="margin:24px 0;">
            <a href="https://www.najdipilota.cz/moje-zpravy.html"
                style="background:#0077B6;color:#fff;text-decoration:none;
                        padding:10px 18px;border-radius:6px;font-size:14px;font-weight:500;">
                Otevřít zprávy a domluvit zakázku
            </a>
            </p>
        `, "Dárek Basic účtu")
    });


    res.json({ success: true, message: `Pilot ${pilotId} upgradován na Basic (${daysNum} dní).`, newCredit: currentCredit - cost }); // days -> daysNum

  } catch (err) {
    await client.query("ROLLBACK");
    console.error('❌ Chyba při sponzorství:', err);
    res.status(500).json({ success: false, message: 'Chyba serveru při sponzorování.' });
  } finally {
    client.release();
  }
});

// ---------------------------------------------------------------------
// 💰 NOVÝ ENDPOINT: Načtení kreditu (pro UI inzerenta)
// ---------------------------------------------------------------------
app.get('/api/advertiser-credit', async (req, res) => {
    const email = req.session?.email || req.query.email;
    if (!email) {
        return res.status(401).json({ credit: 0, error: 'Nepřihlášen' });
    }
    try {
        const result = await pool.query(
            'SELECT credit_balance FROM advertisers WHERE email = $1', 
            [email]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ credit: 0, error: 'Inzerent nenalezen' });
        }
        res.json({ credit: parseFloat(result.rows[0].credit_balance).toFixed(2) });
    } catch (e) {
        console.error('Chyba při načítání kreditu:', e);
        res.status(500).json({ credit: 0, error: 'Chyba serveru' });
    }
});



app.post('/mark-payment-today', async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).send("Chybí ID pilota.");

  try {
    const r = await pool.query(
      `UPDATE pilots 
       SET visible_payment = CURRENT_DATE
       WHERE id = $1
       RETURNING id`,
      [id]
    );

    if (r.rowCount === 0) {
      return res.status(404).send("Pilot nenalezen.");
    }
    res.send("✅ Platba uložena s dnešním datem.");
  } catch (err) {
    console.error("Chyba v /mark-payment-today:", err);
    res.status(500).send("Chyba při ukládání platby.");
  }
});


// Alternativní /admin -> stejná ochrana
app.get('/admin', allowLocalhostOnly, requireAdminLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'admin.html'));
});

// Admin login/logout akce pouze z localhostu
app.post('/admin-login', allowLocalhostOnly, (req, res) => { 

    const { username, password } = req.body;
    const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        return res.json({ success: true });
    }
    return res.status(401).json({ success: false, message: 'Neplatné přihlašovací údaje' });

});
app.get('/admin-logout', allowLocalhostOnly, (req, res) => { 

    req.session.destroy(() => {
        res.redirect('/adminland.html');
    });
});

// Stav session pro přesměrování z admin.html
app.get('/check-admin-session', allowLocalhostOnly, (req, res) => {
  if (req.session.isAdmin) return res.status(200).send('OK');
  return res.status(403).send('Unauthorized');
});

app.post('/contact-pilot', async (req, res) => {
  const { to, message } = req.body;
  if (!to || !message) return res.status(400).send("Chybí e-mail nebo zpráva.");

  try {
    await transporter.sendMail({
      from: '"Dronová mapa" <dronadmin@seznam.cz>',
      to,
      cc: 'dronadmin@seznam.cz', // kopie pro admina
      subject: 'Zpráva od návštěvníka mapy',
      text: message
    });
    res.send("✅ Zpráva byla úspěšně odeslána.");
  } catch (err) {
    console.error("Chyba při odesílání zprávy:", err);
    res.status(500).send("❌ Nepodařilo se odeslat zprávu.");
  }
});

app.post("/update-membership", async (req, res) => {
  const { email, membership_type } = req.body;

  if (!email || !membership_type) {
    return res.status(400).json({ success: false, message: "Chybí e-mail nebo typ členství." });
  }

  // Povolené hodnoty
  const allowedTypes = ["Free", "Basic", "Premium"];
  if (!allowedTypes.includes(membership_type)) {
    return res.status(400).json({ success: false, message: "Neplatný typ členství." });
  }

  try {
    const result = await pool.query(
      `UPDATE pilots SET type_account = $1 WHERE email = $2 RETURNING type_account`,
      [membership_type, email]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: "Pilot nenalezen." });
    }

    res.json({ success: true, message: "Členství bylo aktualizováno.", type_account: result.rows[0].type_account });
  } catch (err) {
    console.error("❌ Chyba při aktualizaci členství:", err);
    res.status(500).json({ success: false, message: "Chyba na serveru." });
  }
});


// --- Vrácení dat přihlášeného pilota ---
app.get('/get-my-pilot', async (req, res) => {
  try {
    let email = req.session?.email || req.query.email || req.headers['x-user-email'];
    let userId = req.session?.userId;

    // Pokud není userId v session, ale máme email, najdeme ho v DB
    if (!userId && email) {
      const userRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [email]);
      if (userRes.rowCount > 0) {
        userId = userRes.rows[0].id;
      }
    }

    if (!userId) {
      return res.status(401).json({ error: 'Nepřihlášen' });
    }

    const result = await pool.query('SELECT * FROM pilots WHERE id = $1', [userId]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Pilot nenalezen' });
    }

    const user = result.rows[0];
    const currentDate = new Date();

    // Kontrola platnosti členství - pouze informativní, bez přepisování DB
    let accountStatus = user.type_account;
    let isExpired = false;
    
    if (user.visible_valid && new Date(user.visible_valid) <= currentDate) {
      isExpired = true;
      // Nastavíme status na "expired", ale NEPŘEPISUJEME databázi
      accountStatus = "Free";
    }

   // načti specialization_ids
const specsRes = await pool.query(
  'SELECT category_id FROM pilot_specializations WHERE pilot_id = $1 ORDER BY category_id',
  [user.id]
);
const specialization_ids = specsRes.rows.map(r => r.category_id);

// vrácení dat vč. specialization_ids (ponecháme původní pole specialization pro kompatibilitu)
res.json({
  ...user,
  specialization_ids,
  type_account: accountStatus,
  membership_expired: isExpired
});
    
  } catch (err) {
    console.error('Chyba při načítání pilota:', err);
    res.status(500).json({ error: 'Chyba na serveru' });
  }
});

// --- Uložení / odvolání souhlasu ---
app.post('/save-consent', async (req, res) => {
  const { email, consent_type, consent_text, granted } = req.body;
  let userId = req.session?.userId;

  try {
    if (!userId && email) {
      const userRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [email]);
      if (userRes.rowCount > 0) {
        userId = userRes.rows[0].id;
      }
    }

    if (!userId) {
      return res.status(401).json({ error: 'Nepřihlášen' });
    }
    
     const timestamp = granted ? new Date() : null;

    if (granted) {
      // Uložíme souhlas do databáze
      await pool.query(
        `INSERT INTO consents (user_id, consent_type, consent_text, ip_address, user_agent, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, consent_type) DO UPDATE SET timestamp = EXCLUDED.timestamp`,
        [userId, consent_type, consent_text, req.ip, req.headers['user-agent'], timestamp]
      );
    } else {
      // Pokud souhlas není udělen, odstraníme záznam
      await pool.query(
        'DELETE FROM consents WHERE user_id = $1 AND consent_type = $2',
        [userId, consent_type]
      );
    }

    res.status(200).json({ success: true, hasPublicConsent: granted, timestamp });
  } catch (err) {
    console.error('Chyba při ukládání souhlasu:', err);
    res.status(500).json({ error: 'Chyba při ukládání souhlasu', detail: err.message });
  }
});

app.get('/get-consent-timestamp', async (req, res) => {
  const { email } = req.query;
  let userId = req.session?.userId;

  try {
    if (!userId && email) {
      const userRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [email]);
      if (userRes.rowCount > 0) {
        userId = userRes.rows[0].id;
      }
    }

    if (!userId) {
      return res.status(401).json({ error: 'Nepřihlášen' });
    }

    // Načteme timestamp souhlasu
    const result = await pool.query(
      `SELECT timestamp FROM consents WHERE user_id = $1 AND consent_type = $2`,
      [userId, 'public_contact'] // Nebo jiný typ souhlasu podle potřeby
    );

    if (result.rowCount > 0) {
      const consentTimestamp = result.rows[0].timestamp;
      res.status(200).json({ timestamp: consentTimestamp });
    } else {
      res.status(404).json({ error: 'Souhlas nebyl nalezen.' });
    }
  } catch (err) {
    console.error('Chyba při načítání souhlasu:', err);
    res.status(500).json({ error: 'Chyba při načítání souhlasu' });
  }
});

app.post('/create-conversation', async (req, res) => {
  const { pilotEmail, advertiserEmail } = req.body;

  try {
    // Get pilot and advertiser details from the database
    const pilotResult = await pool.query('SELECT id FROM pilots WHERE email = $1', [pilotEmail]);
    const advertiserResult = await pool.query('SELECT id FROM advertisers WHERE email = $1', [advertiserEmail]);

    if (pilotResult.rowCount === 0 || advertiserResult.rowCount === 0) {
      return res.status(400).json({ success: false, message: 'Pilot nebo inzerent nenalezen' });
    }

    const pilotId = pilotResult.rows[0].id;
    const advertiserId = advertiserResult.rows[0].id;

    // Check if a conversation already exists between this pilot and advertiser
    const existingConversation = await pool.query(
      'SELECT id, uid FROM conversations WHERE pilot_id = $1 AND advertiser_id = $2 LIMIT 1',
      [pilotId, advertiserId]
    );

    let conversationId;
    let conversationUid;

    if (existingConversation.rowCount > 0) {
      // If the conversation exists, use the existing conversationId
      conversationId = existingConversation.rows[0].id;
      conversationUid = existingConversation.rows[0].uid;
    } else {
      // If no conversation exists, create a new one
      const conversationResult = await pool.query(
        `INSERT INTO conversations (pilot_id, advertiser_id)
         VALUES ($1, $2)
         RETURNING id, uid`,
        [pilotId, advertiserId]
      );

      conversationId = conversationResult.rows[0].id;
      conversationUid = conversationResult.rows[0].uid;
    }

    // ✅ Tahle závorka ti chyběla ↓↓↓↓↓
    res.json({ success: true, conversationId, conversationUid });

  } catch (err) {
    console.error("Chyba při vytváření konverzace:", err);
    res.status(500).json({ success: false, message: 'Chyba serveru při vytváření konverzace' });
  }
});



// GET /get-advertiser-conversations?advertiserEmail=...
app.get('/get-advertiser-conversations', async (req, res) => {
  const { advertiserEmail } = req.query;
  if (!advertiserEmail) return res.json({ success: false, message: 'Missing advertiserEmail' });

  try {
    // 1) Najdi advertiser_id podle e-mailu
    const advRes = await pool.query('SELECT id FROM advertisers WHERE email = $1', [advertiserEmail]);
    if (advRes.rowCount === 0) {
      return res.json({ success: true, conversations: [] });
    }
    const advertiserId = advRes.rows[0].id;

    // 2) Konverzace inzerenta + poslední zpráva + unread (počítané proti conversation_views.user_id = advertiserId)
    const convRes = await pool.query(`
  WITH last_msg AS (
    SELECT DISTINCT ON (m.conversation_id)
           m.conversation_id,
           m.id            AS msg_id,
           m.sender_id     AS last_sender_id,
           m.message       AS last_message,
           m.created_at    AS last_message_time
    FROM messages m
    ORDER BY m.conversation_id, m.created_at DESC
  )
  SELECT
    c.id,
    p.email AS pilot_email,
    p.name  AS pilot_name,
    lm.last_message,
    lm.last_message_time,
    -- unread = poslední zpráva je od druhé strany A je novější než last_seen (nebo last_seen neexistuje)
    CASE
      WHEN lm.msg_id IS NULL THEN FALSE
      WHEN lm.last_sender_id = c.advertiser_id THEN FALSE
      ELSE (lm.last_message_time > COALESCE(cv.last_seen, '1970-01-01'))
    END AS unread
  FROM conversations c
  JOIN pilots p ON p.id = c.pilot_id
  LEFT JOIN conversation_views cv 
         ON cv.conversation_id = c.id AND cv.user_id = $1
  LEFT JOIN last_msg lm 
         ON lm.conversation_id = c.id
  WHERE c.advertiser_id = $1
  ORDER BY lm.last_message_time DESC NULLS LAST
`, [advertiserId]);

    return res.json({ success: true, conversations: convRes.rows });
  } catch (err) {
    console.error('Error fetching advertiser conversations:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});


app.get('/get-messages', async (req, res) => {
  const { conversationId } = req.query;

  try {
    const result = await pool.query(
       `SELECT 
         m.id, m.sender_id, m.message, 
         m.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Prague' AS created_at,
         CASE WHEN m.sender_id = c.pilot_id THEN p.email ELSE a.email END AS sender_email,
         CASE WHEN m.sender_id = c.pilot_id THEN 'pilot' ELSE 'advertiser' END AS sender_role
       FROM messages m
       JOIN conversations c ON c.id = m.conversation_id
       JOIN pilots p ON p.id = c.pilot_id
       JOIN advertisers a ON a.id = c.advertiser_id
       WHERE m.conversation_id = $1
       ORDER BY m.created_at ASC`,
      [conversationId]
    );

    res.json({ success: true, messages: result.rows });
  } catch (e) {
    console.error("Chyba při načítání zpráv:", e);
    res.status(500).json({ success: false, message: 'Chyba při načítání zpráv' });
  }
});

// Počet nepřečtených zpráv pro pilota
app.get('/unread-count', async (req, res) => {
  try {
    const email =
      (req.query.pilotEmail || req.query.email || req.session?.email || '').toLowerCase();
    if (!email) return res.json({ count: 0 });

    const p = await pool.query('SELECT id FROM pilots WHERE LOWER(email) = $1', [email]);
    if (p.rowCount === 0) return res.json({ count: 0 });
    const pilotId = p.rows[0].id;

    const r = await pool.query(`
      SELECT COUNT(*)::int AS n
      FROM messages m
      JOIN conversations c ON c.id = m.conversation_id
      LEFT JOIN conversation_views cv
        ON cv.conversation_id = c.id AND cv.user_id = c.pilot_id
      WHERE c.pilot_id = $1
        AND m.sender_id = c.advertiser_id
        AND m.created_at > COALESCE(cv.last_seen, '1970-01-01'::timestamp)
    `, [pilotId]);

    res.json({ count: r.rows[0].n });
  } catch (e) {
    console.error('unread-count error', e);
    res.status(500).json({ count: 0 });
  }
});

// Nový endpoint pro získání jména pilota podle ID
app.get('/get-pilot-name-by-id', async (req, res) => {
  const { id } = req.query;
  if (!id) {
    return res.status(400).json({ success: false, message: 'Missing pilot ID' });
  }

  try {
    const result = await pool.query('SELECT name FROM pilots WHERE id = $1', [id]);
    if (result.rowCount > 0) {
      res.json({ success: true, name: result.rows[0].name });
    } else {
      res.json({ success: false, message: 'Pilot not found' });
    }
  } catch (err) {
    console.error("Error fetching pilot name by ID:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Nový endpoint pro získání jména inzerenta podle ID
app.get('/get-advertiser-name-by-id', async (req, res) => {
  const { id } = req.query;
  if (!id) {
    return res.status(400).json({ success: false, message: 'Missing advertiser ID' });
  }

  try {
    const result = await pool.query('SELECT name FROM advertisers WHERE id = $1', [id]);
    if (result.rowCount > 0) {
      res.json({ success: true, name: result.rows[0].name });
    } else {
      res.json({ success: false, message: 'Advertiser not found' });
    }
  } catch (err) {
    console.error("Error fetching advertiser name by ID:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Vrátí DB id podle e-mailu a role (pilot|advertiser)
app.get('/get-user-id', async (req, res) => {
  try {
    const { email, type } = req.query; // type: 'pilot' | 'advertiser'
    if (!email || !type) return res.status(400).json({ error: 'Missing email or type' });

    const lower = String(email).toLowerCase();
    const sql = type === 'pilot'
      ? 'SELECT id FROM pilots WHERE LOWER(email) = $1'
      : 'SELECT id FROM advertisers WHERE LOWER(email) = $1';

    const r = await pool.query(sql, [lower]);
    if (!r.rowCount) return res.status(404).json({ error: 'User not found' });

    res.json({ id: r.rows[0].id });
  } catch (e) {
    console.error('get-user-id error', e);
    res.status(500).json({ error: 'Failed to resolve user id' });
  }
});



app.post('/create-conversation', async (req, res) => {
  const { pilotEmail, advertiserEmail } = req.body;

  try {
    // Získáme pilot ID
    const pilotResult = await pool.query('SELECT id FROM pilots WHERE email = $1', [pilotEmail]);
    if (pilotResult.rowCount === 0) {
      return res.status(400).json({ success: false, message: 'Pilot nenalezen' });
    }

    const pilotId = pilotResult.rows[0].id;

    // Pokusíme se zjistit, zda je advertiser v tabulce advertisers nebo pilots
    let advertiserId = null;
    let advertiserTable = 'advertisers';

    const advertiserResult = await pool.query('SELECT id FROM advertisers WHERE email = $1', [advertiserEmail]);
    if (advertiserResult.rowCount > 0) {
      advertiserId = advertiserResult.rows[0].id;
      advertiserTable = 'advertisers';
    } else {
      const pilotAsAdvertiserResult = await pool.query('SELECT id FROM pilots WHERE email = $1', [advertiserEmail]);
      if (pilotAsAdvertiserResult.rowCount > 0) {
        advertiserId = pilotAsAdvertiserResult.rows[0].id;
        advertiserTable = 'pilots';
      }
    }

    if (!advertiserId) {
      return res.status(400).json({ success: false, message: 'Inzerent nenalezen' });
    }

    // Zabráníme self-konverzaci
    if (advertiserId === pilotId && advertiserTable === 'pilots') {
      return res.status(400).json({ success: false, message: 'Nelze vytvořit konverzaci se stejným uživatelem' });
    }

    // Zkontroluj, zda konverzace už neexistuje (včetně tabulky)
    const existingConversation = await pool.query(
      `SELECT id FROM conversations WHERE pilot_id = $1 AND advertiser_id = $2 AND advertiser_table = $3 LIMIT 1`,
      [pilotId, advertiserId, advertiserTable]
    );

    let conversationId;
    if (existingConversation.rowCount > 0) {
      conversationId = existingConversation.rows[0].id;
    } else {
      const conversationResult = await pool.query(
        `INSERT INTO conversations (pilot_id, advertiser_id, advertiser_table)
         VALUES ($1, $2, $3)
         RETURNING id`,
        [pilotId, advertiserId, advertiserTable]
      );
      conversationId = conversationResult.rows[0].id;
    }

    res.json({ success: true, conversationId });

  } catch (err) {
    console.error("❌ Chyba při vytváření konverzace:", err);
    res.status(500).json({ success: false, message: 'Chyba serveru při vytváření konverzace' });
  }
});

app.post("/send-contact", async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).send("Vyplňte všechna pole.");
  }

  try {
    await transporter.sendMail({
  from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
  to: "dronadmin@seznam.cz",
  subject: "Nová zpráva z kontaktního formuláře",
  text: `Od: ${name} <${email}>\n\n${message}`,
  replyTo: email
});
    res.send("✅ Zpráva byla odeslána.");
  } catch (err) {
    console.error("❌ Chyba při odesílání:", err);
    res.status(500).send("Nepodařilo se odeslat zprávu: " + err.message);
  }
});




app.get('/blog/article/:id', async (req, res) => {
  const articleId = req.params.id;
  try {
    // Načteme konkrétní článek podle ID
    const result = await pool.query('SELECT * FROM articles WHERE id = $1', [articleId]);
    const article = result.rows[0];
    if (article) {
      res.render('article', { article });
    } else {
      res.status(404).send('Článek nebyl nalezen');
    }
  } catch (err) {
    console.error('Chyba při načítání článku:', err);
    res.status(500).send('Chyba na serveru');
  }
});




// Get pilot's name by email
/*
app.get('/get-pilot-name', async (req, res) => {
  const { email } = req.query;
  
  try {
    const result = await pool.query(
      'SELECT name FROM pilots WHERE email = $1',
      [email]
    );
    
    if (result.rowCount > 0) {
      res.json({ success: true, name: result.rows[0].name });
    } else {
      res.json({ success: false, message: 'Pilot not found' });
    }
  } catch (err) {
    console.error("Error fetching pilot name:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
*/

// Get all conversations for a pilot
/*
app.get('/get-pilot-conversations', async (req, res) => {
  const { pilotEmail } = req.query;

  try {
    // Najdi ID pilota podle emailu
    const pilotResult = await pool.query(
      'SELECT id FROM pilots WHERE email = $1',
      [pilotEmail]
    );

    if (pilotResult.rowCount === 0) {
      return res.json({ success: false, message: 'Pilot not found' });
    }

    const pilotId = pilotResult.rows[0].id;

    // Načti všechny konverzace pilota (včetně typu tabulky advertiser_table)
    const conversations = await pool.query(`
      SELECT 
        c.id,
        c.advertiser_table,
        CASE
          WHEN c.advertiser_table = 'advertisers' THEN a.email
          ELSE p2.email
        END AS advertiser_email,
        CASE
          WHEN c.advertiser_table = 'advertisers' THEN a.name
          ELSE p2.name
        END AS advertiser_name,

        (SELECT message 
         FROM messages 
         WHERE conversation_id = c.id 
         ORDER BY created_at DESC 
         LIMIT 1) AS last_message,

        (SELECT created_at 
         FROM messages 
         WHERE conversation_id = c.id 
         ORDER BY created_at DESC 
         LIMIT 1) AS last_message_time,

        EXISTS (
          SELECT 1 FROM messages 
          WHERE conversation_id = c.id 
          AND sender_id != $1 
          AND (created_at > (
            SELECT last_seen 
            FROM conversation_views 
            WHERE conversation_id = c.id AND user_id = $1
            LIMIT 1
          ) OR NOT EXISTS (
            SELECT 1 
            FROM conversation_views 
            WHERE conversation_id = c.id AND user_id = $1
          ))
        ) AS unread

      FROM conversations c
      JOIN pilots p ON c.pilot_id = p.id
      LEFT JOIN advertisers a ON c.advertiser_table = 'advertisers' AND c.advertiser_id = a.id
      LEFT JOIN pilots p2 ON c.advertiser_table = 'pilots' AND c.advertiser_id = p2.id
      WHERE c.pilot_id = $1
      ORDER BY last_message_time DESC NULLS LAST
    `, [pilotId]);

    res.json({
      success: true,
      conversations: conversations.rows
    });
  } catch (err) {
    console.error("❌ Error fetching pilot conversations:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
*/


// Mark conversation as read
app.post('/mark-as-read', async (req, res) => {
  const { conversationId, userEmail } = req.body;
  if (!conversationId || !userEmail) {
    return res.status(400).json({ success: false, message: "Missing params" });
  }

  try {
    // Označíme všechny zprávy v konverzaci, které NEJSOU od uživatele
    await pool.query(`
      UPDATE messages
      SET read = TRUE
      WHERE conversation_id = $1
        AND sender_email <> $2
        AND read = FALSE
    `, [conversationId, userEmail]);

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Chyba při mark-as-read:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/mark-as-seen', async (req, res) => {
  const { conversationId, userId } = req.body;
  console.log("📩 mark-as-seen:", conversationId, userId);   // DEBUG

  if (!conversationId || !userId) {
    return res.status(400).json({ success: false, message: "Missing params" });
  }

  try {
    await pool.query(`
      INSERT INTO conversation_views (conversation_id, user_id, last_seen)
      VALUES ($1, $2, NOW())
      ON CONFLICT (conversation_id, user_id)
      DO UPDATE SET last_seen = EXCLUDED.last_seen
    `, [conversationId, userId]);

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Chyba při mark-as-seen:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});




// Změna hesla (pilot)
app.post('/change-password', changePassLimiter, async (req, res) => {
  try {
    const { email, oldPassword, newPassword } = req.body;
    if (!email || !oldPassword || !newPassword) {
      return res.status(400).send('Chybí údaje.');
    }

    // (Volitelné, ale doporučené) – ověř, že mění heslo přihlášený uživatel
    if (req.session?.email && req.session.email !== email) {
      return res.status(403).send('Nemůžeš měnit heslo jinému účtu.');
    }

    const r = await pool.query('SELECT id, password_hash FROM pilots WHERE email = $1', [email]);
    if (r.rowCount === 0) return res.status(404).send('Uživatel nenalezen.');

    const ok = await bcrypt.compare(oldPassword, r.rows[0].password_hash);
    if (!ok) return res.status(401).send('Staré heslo není správné.');

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE pilots SET password_hash = $1 WHERE email = $2', [hash, email]);

    return res.status(200).send('Heslo bylo úspěšně změněno.');
  } catch (err) {
    console.error('Chyba při změně hesla:', err);
    return res.status(500).send('Chyba na serveru při změně hesla');
  }
});

// Kdo je přihlášen jako inzerent (ze session)?
app.get('/get-my-advertiser', async (req, res) => {
  try {
    const email = (req.session?.email || '').toLowerCase();
    if (!email) return res.status(401).json({});

    const r = await pool.query('SELECT id, email, name FROM advertisers WHERE LOWER(email) = $1', [email]);
    if (r.rowCount === 0) return res.status(401).json({});
    res.json(r.rows[0]);
  } catch (e) {
    console.error('get-my-advertiser error', e);
    res.status(500).json({});
  }
});



// GET /poptavky – veřejné i „moje“
app.get('/poptavky', async (req, res) => {
  try {
    const { region = '', mine = '0' } = req.query;
    const sessionEmail = (req.session?.email || '').toLowerCase();

    if (mine === '1' && sessionEmail) {
      // moje poptávky (nezávisle na public)
      const r = await pool.query(
        `SELECT id, title, description, location, region, budget, deadline, advertiser_email, created_at, status
         FROM demands
         WHERE LOWER(advertiser_email) = $1
         ORDER BY created_at DESC`,
         [sessionEmail]
      );
      return res.json(r.rows);
    }

    // veřejné poptávky (volitelně s filtrem kraje)
    const params = [];
    let where = `public = TRUE`;
    if (region) { params.push(region); where += ` AND region = $${params.length}`; }

     const r = await pool.query(
      `SELECT id, title, description, location, region, budget, deadline, advertiser_email, created_at, status
       FROM demands
       WHERE ${where}
       ORDER BY created_at DESC`,
      params
    );
    res.json(r.rows);
  } catch (err) {
    console.error("Chyba při načítání poptávek:", err);
    res.status(500).send("Chyba serveru při načítání poptávek");
  }
});

app.put('/poptavky/:id/status', async (req, res) => {
  const { id } = req.params;
  const { status, satisfaction, note } = req.body; // ✨ přidáno hodnocení a poznámka
  const email = req.session?.email || req.body.email; // inzerent v session

  if (!['Zpracovává se', 'Hotovo'].includes(status)) {
    return res.status(400).json({ error: 'Neplatný stav' });
  }

  try {
    // ověření vlastnictví
    const check = await pool.query(
      `SELECT advertiser_email FROM demands WHERE id = $1`, [id]
    );
    if (check.rowCount === 0)
      return res.status(404).json({ error: 'Poptávka nenalezena' });

    if (check.rows[0].advertiser_email !== email)
      return res.status(403).json({ error: 'Nemáte oprávnění měnit tuto poptávku' });

    // 🔹 update včetně hodnocení, pokud je zasláno
    await pool.query(`
      UPDATE demands
      SET status = $1,
          satisfaction = COALESCE($2, satisfaction),
          satisfaction_note = COALESCE($3, satisfaction_note)
      WHERE id = $4
    `, [status, satisfaction || null, note || null, id]);

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Chyba při změně stavu poptávky:', err);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});



// POST /poptavky – vložení poptávky inzerentem
app.post('/poptavky', async (req, res) => {
  try {
    const { title, description, location, region, budget, deadline, public: isPublic } = req.body;
    const advertiser_email = (req.session?.email || '').toLowerCase();

    if (!advertiser_email) return res.status(401).send('Nepřihlášený inzerent.');
    if (!title || !location) return res.status(400).send('Chybí povinná pole (název a lokalita).');

    // 🔧 úprava budget
    let budgetValue = null;
    if (budget === 'dohodou') {
      budgetValue = 'dohodou';
    } else if (budget !== null && budget !== '' && !isNaN(budget)) {
      budgetValue = Number(budget);
    }

    const inserted = await pool.query(
      `INSERT INTO demands
       (title, description, location, region, budget, deadline, public, advertiser_email)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, title, description, location, region, budget, deadline, advertiser_email, created_at`,
      [
        title || null,
        description || null,
        location || null,
        region || null,
        budgetValue,     // 📌 už ne Number(), ale naše logika výše
        deadline || null,
        isPublic !== false, // default true
        advertiser_email
      ]
    );

    const demand = inserted.rows[0];

    // 2) Najít Premium piloty
    const pilotsRes = await pool.query(`
      SELECT id, COALESCE(NULLIF(name,''), 'Pilot') AS name, email
      FROM pilots
      WHERE type_account = 'Premium'
        AND email IS NOT NULL AND email <> ''
    `);

    // 3) Poslat upozornění každému Premium pilotovi
    for (const p of pilotsRes.rows) {
      try {
        const html = buildNewDemandAlertEmail(p.name, demand);
        await transporter.sendMail({
          from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
          to: p.email,
          bcc: 'drboom@seznam.cz',
          subject: 'Nová poptávka na NajdiPilota.cz',
          html
        });
      } catch (e) {
        console.error(`❌ Nepodařilo se poslat Premium alert ${p.email}:`, e.message);
      }
    }

    res.status(201).json(inserted.rows[0]);
  } catch (err) {
    console.error('Chyba při ukládání poptávky:', err);
    res.status(500).send('Chyba serveru při ukládání poptávky');
  }
});


app.get('/__dbinfo', async (req,res) => {
  const r = await pool.query(`SELECT current_database(), current_user, inet_server_addr(), inet_server_port()`);
  res.json(r.rows[0]);
});


app.get('/categories', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name FROM categories ORDER BY name');
    const fixed = rows.map(r => ({ ...r, name: bestUtfVariant(r.name) }));
    res.set('Content-Type', 'application/json; charset=utf-8');
    res.set('Cache-Control', 'no-store');
    res.json(fixed);
  } catch (err) {
    console.error('Chyba /categories:', err);
    res.status(500).json([]);
  }
});


// Nastavení složky pro statické soubory
app.use(express.static(path.join(__dirname, 'public')));

// pokud máš prerender, vynech ho pro /categories (nebo ho dej níž)
app.use((req, res, next) => {
  if (req.path.startsWith('/categories')) return next();
  return prerender(req, res, next);
});

// 1) prostý UTF-8 ping (ověří transport)
app.get('/utf8-ping', (req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.json({ sample: 'Školení pro pokročilé piloty – údržba, měření, zkoušky' });
});

// 2) fingerprint DB + ukázka kategorií
app.get('/db-fingerprint', async (req, res) => {
  const meta = await pool.query(`
    SELECT current_database() AS db,
           current_user       AS "user",
           current_setting('server_version')  AS server_version,
           current_setting('server_encoding') AS server_encoding,
           current_setting('client_encoding') AS client_encoding
  `);
  const cnt = await pool.query('SELECT COUNT(*)::int AS n FROM categories');
  const sample = await pool.query('SELECT id, name FROM categories ORDER BY id LIMIT 5');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.json({ meta: meta.rows[0], categories_count: cnt.rows[0].n, sample: sample.rows });
});


// Změna mailu
function buildChangeEmailEmail(oldEmail, newEmail) {
  return `
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
      <h2 style="color: #0077B6;">✉️ Změna e-mailové adresy</h2>
      <p style="font-size: 16px; color: #495057;">
        Dobrý den,
      </p>
      <p style="font-size: 16px; color: #495057;">
        právě byla provedena změna e-mailu vašeho účtu na <strong style="color:#0077B6;">NajdiPilota.cz</strong>.
      </p>

      <p style="font-size: 16px; color: #495057;">
        <strong>Starý e-mail:</strong> ${oldEmail}<br>
        <strong>Nový e-mail:</strong> ${newEmail}
      </p>

      <p style="font-size: 16px; color: #495057;">
        Pokud jste tuto změnu provedli vy, není potřeba žádná další akce.  
        Pokud jste změnu neprovedli, <strong style="color:red;">ihned nás kontaktujte</strong> na 
        <a href="mailto:dronadmin@seznam.cz" style="color:#0077B6;">dronadmin@seznam.cz</a>.
      </p>

      <hr style="margin:20px 0;">

      <p style="font-size: 14px; color: #6c757d;">
        Tento e-mail byl odeslán automaticky. Prosíme, neodpovídejte na něj přímo.
      </p>

      <p style="font-size: 16px; color: #495057;">S pozdravem,<br>Tým NajdiPilota.cz</p>
    </div>
  `;
}




// Funkce pro opravu kódování z databáze
function fixDatabaseEncoding(str) {
  if (typeof str !== 'string') return str;
  
  // Opravy pro běžné problémy s kódováním z databáze
  const encodingMap = {
    'Ã¡': 'á', 'Ã©': 'é', 'Ã­': 'í', 'Ã³': 'ó', 'Ãº': 'ú', 'Ã½': 'ý',
    'Ã': 'Á', 'Ã': 'É', 'Ã': 'Í', 'Ã': 'Ó', 'Ã': 'Ú', 'Ã': 'Ý',
    'Ã¤': 'ä', 'Ã«': 'ë', 'Ã¯': 'ï', 'Ã¶': 'ö', 'Ã¼': 'ü',
    'Ã': 'Ä', 'Ã': 'Ë', 'Ã': 'Ï', 'Ã': 'Ö', 'Ã': 'Ü',
    'Ã': 'È', 'Ã': 'ß', 'Ã°': 'ð', 'Ã¦': 'æ', 'Â': '',
    'â€"': '—', 'â€“': '–', 'â€˜': '‘', 'â€™': '’', 'â€œ': '“', 'â€': '”',
    'Ã½': 'ý', 'Ã¡': 'á', 'Ã©': 'é', 'Ã­': 'í', 'Ã³': 'ó', 'Ãº': 'ú',
    'Ã¯': 'ï', 'Ã¶': 'ö', 'Ã¼': 'ü', 'Ã§': 'ç', 'Ã¸': 'ø', 'Ã¥': 'å',
    'Ã±': 'ñ', 'Ãµ': 'õ', 'Ãª': 'ê', 'Ã¹': 'ù', 'Ã¬': 'ì', 'Ã²': 'ò',
    'Ã¢': 'â', 'Ã»': 'û', 'Ã®': 'î', 'Ã´': 'ô', 'Ã¨': 'è', 'Ã ': 'à'
  };
  
  let result = str;
  for (const [wrong, correct] of Object.entries(encodingMap)) {
    result = result.replace(new RegExp(wrong, 'g'), correct);
  }
  
  return result;
}


// PUT /poptavky/:id – update jen vlastník
app.put('/poptavky/:id', async (req, res) => {
  try {
    const id = +req.params.id;
    const { title, description, location, region, budget, deadline, public: isPublic } = req.body;
    const advertiser_email = (req.session?.email || '').toLowerCase();
    if (!advertiser_email) return res.status(401).send("Nepřihlášený inzerent.");

    const owner = await pool.query(`SELECT LOWER(advertiser_email) AS advertiser_email FROM demands WHERE id = $1`, [id]);

    if (owner.rowCount === 0) return res.status(404).send("Poptávka nenalezena.");
    if (owner.rows[0].advertiser_email !== advertiser_email) return res.status(403).send("Nesmíš upravovat cizí poptávku.");

    const r = await pool.query(
      `UPDATE demands SET
         title = COALESCE($2,title),
         description = COALESCE($3,description),
         location = COALESCE($4,location),
         region = COALESCE($5,region),
         budget = $6,
         deadline = $7,
         public = COALESCE($8, public)
       WHERE id = $1
       RETURNING id, title, description, location, region, budget, deadline, advertiser_email, created_at`,
      [id, title || null, description || null, location || null, region || null,
       Number.isFinite(+budget) ? +budget : null, deadline || null,
       typeof isPublic === 'boolean' ? isPublic : null]
    );
    res.json(r.rows[0]);
  } catch (err) {
    console.error("Chyba při update poptávky:", err);
    res.status(500).send("Chyba serveru při update poptávky");
  }
});

// DELETE /poptavky/:id – s ověřením vlastníka
app.delete('/poptavky/:id', async (req, res) => {
  try {
    const id = +req.params.id;
    const advertiser_email = (req.session?.email || '').toLowerCase();
    if (!advertiser_email) return res.status(401).send("Nepřihlášený inzerent.");

    const owner = await pool.query(`SELECT LOWER(advertiser_email) AS advertiser_email FROM demands WHERE id = $1`, [id]);
    if (owner.rowCount === 0) return res.status(404).send("Poptávka nenalezena.");
    if (owner.rows[0].advertiser_email !== advertiser_email) return res.status(403).send("Nesmíš mazat cizí poptávku.");

    await pool.query(`DELETE FROM demands WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Chyba při mazání poptávky:", err);
    res.status(500).send("Chyba serveru při mazání poptávky");
  }
});




app.get('/send-expiry-emails', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT email, visible_valid 
      FROM pilots 
      WHERE visible_valid IS NOT NULL
    `);

    for (const pilot of result.rows) {
      const daysLeft = Math.ceil(
        (new Date(pilot.visible_valid) - new Date()) / (1000 * 60 * 60 * 24)
      );

      if (daysLeft === 7) {
        await transporter.sendMail({
          from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
          to: pilot.email,
          bcc: 'drboom@seznam.cz',
          subject: "Vaše členství vyprší za 7 dní",
          html: membershipExpiry7DaysEmail(pilot.email)
        });
      }

      if (daysLeft === 3) {
        await transporter.sendMail({
          from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
          to: pilot.email,
          bcc: 'drboom@seznam.cz',
          subject: "Vaše členství vyprší za 3 dny",
          html: membershipExpiry3DaysEmail(pilot.email)
        });
      }
    }

    res.send("✅ Expirační e-maily byly odeslány.");
  } catch (err) {
    console.error("Chyba při odesílání expiračních e-mailů:", err);
    res.status(500).send("❌ Chyba při odesílání.");
  }
});

app.post('/admin-send-gdpr-reminder', requireAdminLogin, async (req, res) => {
  try {
    await transporter.verify();
    console.log('📡 Email server connection is ready');

    // 1️⃣ Získání seznamu pilotů
    let query = `
      SELECT p.id, p.email, p.name, p.type_account
      FROM pilots p
      LEFT JOIN consents c ON p.id = c.user_id AND c.consent_type = 'public_contact'
      WHERE p.type_account IN ('Premium', 'Basic')
    `;
    let queryParams = [];

    if (req.body.ids && req.body.ids.length > 0) {
      query += ` AND p.id IN (${req.body.ids.map((_, i) => `$${i + 1}`).join(',')})`;
      queryParams = [...req.body.ids];
    }

    const result = await pool.query({
      text: query,
      values: queryParams,
      timeout: 10000
    });

    const pilotsWithoutConsent = result.rows;
    if (pilotsWithoutConsent.length === 0) {
      return res.send("Žádní piloti nevyžadují připomenutí GDPR souhlasu.");
    }

    let successCount = 0;
    let failedEmails = [];

    // 2️⃣ Odeslání e-mailů
    for (const pilot of pilotsWithoutConsent) {
      try {
        const innerHtml = `
          <p>Dobrý den, <strong>${escapeHtml(pilot.name || '')}</strong>,</p>
          <p>
            děkujeme, že jste součástí komunity <strong style="color:#0077B6;">NajdiPilota.cz</strong>.
            Váš účet <strong>${escapeHtml(pilot.type_account)}</strong> zatím nemá udělen souhlas se
            zobrazením kontaktů (GDPR).
          </p>
          <p>
            Bez tohoto souhlasu se váš profil nemusí zobrazovat ve veřejném přehledu pilotů.
            Kliknutím na tlačítko níže se můžete přihlásit a souhlas snadno potvrdit:
          </p>
          <p style="margin:24px 0;">
            <a href="https://www.najdipilota.cz/login.html"
               style="background:#0077B6;color:#fff;text-decoration:none;
                      padding:10px 18px;border-radius:6px;font-size:14px;font-weight:500;">
              Přihlaš se a uděl souhlas GDPR
            </a>
          </p>
          <p>
            Děkujeme vám za spolupráci a těšíme se na další společné lety! 🛩️<br>
            <strong>Tým NajdiPilota.cz</strong>
          </p>
          <p style="font-size:13px;color:#6c757d;">
            Tento e-mail je automaticky generován systémem NajdiPilota.cz.<br>
            <a href="https://www.najdipilota.cz/o-projektu.html" style="color:#0077B6;">O projektu</a> |
            <a href="https://www.najdipilota.cz/faq.html" style="color:#0077B6;">FAQ</a>
          </p>
        `;

        const html = wrapEmailContent(innerHtml, "GDPR připomínka – NajdiPilota.cz");

        const text = `
Dobrý den ${pilot.name},

děkujeme, že jste součástí komunity NajdiPilota.cz.

Váš účet je ${pilot.type_account}, ale chybí nám váš souhlas se zobrazením kontaktů.

Pokud chcete udělit souhlas s GDPR, přihlaste se na:
https://www.najdipilota.cz/moje-udaje.html

Po přihlášení budete mít možnost souhlas s GDPR udělit.

Dotazy: dronadmin@seznam.cz

S pozdravem,
Tým NajdiPilota.cz
`;

        await transporter.sendMail({
          from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
          to: pilot.email,
          subject: "📋 Potvrďte GDPR souhlas – NajdiPilota.cz",
          html,
          text
        });

        successCount++;
        console.log(`✅ GDPR reminder sent to: ${pilot.email}`);
        await new Promise(resolve => setTimeout(resolve, 500));
      } catch (err) {
        console.error(`❌ Error sending to ${pilot.email}:`, err.message);
        failedEmails.push(pilot.email);
      }
    }

    // 3️⃣ Výsledek
    let response = `GDPR připomínky odeslány: ${successCount} úspěšně z ${pilotsWithoutConsent.length} pilotů.`;
    if (failedEmails.length > 0) {
      response += `\n\nNepodařilo se odeslat na: ${failedEmails.join(', ')}`;
    }

    res.send(response);
  } catch (err) {
    console.error("❌ Chyba při odesílání GDPR připomínek:", err);
    res.status(500).send(`Chyba při odesílání: ${err.message}`);
  }
});



// Route pro přístup k 'onlymap.html'
app.get('/onlymap.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'onlymap.html'));
});

// Route pro přístup k 'chat.html' ve složce 'onlymap.html'
app.get('/onlymap.html/chat.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// Výchozí route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Spuštění serveru
const PORT = process.env.PORT || 3000;
app.use((err, req, res, next) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
  next();
    console.error('❌ Chyba:', err.stack);
    res.status(500).json({ error: 'Interní chyba serveru' });
});

// ✅ Admin výpis poptávek (všechny stavy)
app.get('/api/admin/demands', async (req, res) => {
  try {
    // Ověření přihlášení nebo IP adresy (máš už middleware allowLocalhostOnly)
    // Použij, pokud chceš přístup omezit:
    // if (!req.session.admin && !allowLocalhost(req)) return res.sendStatus(403);

    const { rows } = await pool.query(`
      SELECT id, title, description, location, region, budget, deadline,
             advertiser_email, created_at, status, satisfaction, satisfaction_note
      FROM demands
      ORDER BY created_at DESC;
    `);
    res.json(rows);
  } catch (err) {
    console.error('❌ Chyba při načítání všech poptávek:', err);
    res.status(500).json({ error: 'Chyba při načítání poptávek.' });
  }
});

// =======================================================
// NOVÉ ENDPOINTY PRO CHAT S POUŽITÍM ID
// =======================================================

// 1. Endpoint pro získání konverzací pilota podle ID
app.get('/api/v2/pilot-conversations', async (req, res) => {
  const { pilotId } = req.query; // Čteme ID z URL
  if (!pilotId) {
    return res.status(400).json({ success: false, message: 'Missing pilotId' });
  }

  try {
    const conversations = await pool.query(`
      SELECT 
        c.id,
        c.uid,
        c.advertiser_id, -- Přidáno, aby se ID předalo na frontend
        c.pilot_id,      -- Přidáno, aby se ID předalo na frontend
        c.advertiser_table,
        CASE
          WHEN c.advertiser_table = 'advertisers' THEN a.email
          ELSE p2.email
        END AS advertiser_email,
        CASE
          WHEN c.advertiser_table = 'advertisers' THEN a.name
          ELSE p2.name
        END AS advertiser_name,

        (SELECT message 
         FROM messages 
         WHERE conversation_id = c.id 
         ORDER BY created_at DESC 
         LIMIT 1) AS last_message,

        (SELECT created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Prague'
 FROM messages
 WHERE conversation_id = c.id
 ORDER BY created_at DESC
 LIMIT 1) AS last_message_time,

        EXISTS (
          SELECT 1 FROM messages 
          WHERE conversation_id = c.id 
          AND sender_id != $1 
          AND (created_at > (
            SELECT last_seen 
            FROM conversation_views 
            WHERE conversation_id = c.id AND user_id = $1
            LIMIT 1
          ) OR NOT EXISTS (
            SELECT 1 
            FROM conversation_views 
            WHERE conversation_id = c.id AND user_id = $1
          ))
        ) AS unread

      FROM conversations c
      JOIN pilots p ON c.pilot_id = p.id
      LEFT JOIN advertisers a ON c.advertiser_table = 'advertisers' AND c.advertiser_id = a.id
      LEFT JOIN pilots p2 ON c.advertiser_table = 'pilots' AND c.advertiser_id = p2.id
      WHERE c.pilot_id = $1
      ORDER BY last_message_time DESC NULLS LAST
    `, [pilotId]);

    res.json({
      success: true,
      conversations: conversations.rows
    });
  } catch (err) {
    console.error("❌ Error fetching pilot conversations:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ✅ Získání konverzace podle UID (např. /api/v2/conversation/f1a1bfc81c32)
app.get('/api/v2/conversation/:uid', async (req, res) => {
  const { uid } = req.params;
  const userId = req.query.userId || null; // volitelně můžeš posílat i ID uživatele z frontendu

  try {
    const result = await pool.query(`
      SELECT 
        c.id,
        c.uid,
        c.pilot_id,
        c.advertiser_id,
        c.advertiser_table,
        p.name AS pilot_name,
        p.email AS pilot_email,
        a.name AS advertiser_name,
        a.email AS advertiser_email,
        c.created_at,
        c.updated_at,
        CASE 
          WHEN $2::integer = c.pilot_id THEN 'pilot'
          WHEN $2::integer = c.advertiser_id THEN 'advertiser'
          ELSE NULL
        END AS current_user_role
      FROM conversations c
      LEFT JOIN pilots p ON c.pilot_id = p.id
      LEFT JOIN advertisers a ON c.advertiser_table = 'advertisers' AND c.advertiser_id = a.id
      WHERE c.uid = $1
      LIMIT 1
    `, [uid, userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Konverzace s tímto UID nenalezena' });
    }

    res.json({
      success: true,
      conversation: result.rows[0]
    });

  } catch (err) {
    console.error("❌ Chyba při načítání konverzace podle UID:", err);
    res.status(500).json({ success: false, message: 'Chyba serveru při načítání konverzace podle UID' });
  }
});



// 2. Endpoint pro získání konverzací inzerenta podle ID
app.get('/api/v2/advertiser-conversations', async (req, res) => {
  const { advertiserId } = req.query;
  if (!advertiserId) {
    return res.status(400).json({ success: false, message: 'Missing advertiserId' });
  }

  try {
    const conversations = await pool.query(`
      SELECT
        c.id,
        c.uid,
        c.pilot_id,
        c.advertiser_id,
        p.name AS pilot_name,
        p.email AS pilot_email,
        (SELECT message
         FROM messages
         WHERE conversation_id = c.id
         ORDER BY created_at DESC
         LIMIT 1) AS last_message,
        (SELECT created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Europe/Prague'
 FROM messages
 WHERE conversation_id = c.id
 ORDER BY created_at DESC
 LIMIT 1) AS last_message_time,
        EXISTS (
          SELECT 1 FROM messages
          WHERE conversation_id = c.id
          AND sender_id != $1 AND created_at > COALESCE((SELECT last_seen FROM conversation_views WHERE conversation_id = c.id AND user_id = $1), '1970-01-01')
        ) AS unread
      FROM conversations c
      JOIN pilots p ON c.pilot_id = p.id
      WHERE c.advertiser_id = $1
      ORDER BY last_message_time DESC NULLS LAST
    `, [advertiserId]);

    res.json({
      success: true,
      conversations: conversations.rows
    });
  } catch (err) {
    console.error("❌ Error fetching advertiser conversations:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});


// 3. Endpoint pro odesílání zpráv pomocí ID
app.post('/api/v2/send-message', async (req, res) => {
  const { conversationId, senderId, message } = req.body;

  if (!conversationId || !senderId || !message) {
      return res.status(400).json({ success: false, message: 'Missing required parameters' });
  }

  try {
    // 1) Účastníci konverzace
    const convRes = await pool.query(
      'SELECT pilot_id, advertiser_id FROM conversations WHERE id = $1',
      [conversationId]
    );
    if (convRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Konverzace nenalezena' });
    }
    const { pilot_id, advertiser_id } = convRes.rows[0];

    // Ověření, že odesílatel patří do konverzace
    if (senderId != pilot_id && senderId != advertiser_id) {
        return res.status(403).json({ success: false, message: 'Odesílatel do konverzace nepatří' });
    }

    // 2) Ulož zprávu
    const inserted = await pool.query(
      `INSERT INTO messages (conversation_id, sender_id, message)
       VALUES ($1, $2, $3)
       RETURNING id, sender_id, message, created_at`,
      [conversationId, senderId, message]
    );
    const newMessage = inserted.rows[0];

    // 3) Enriched zpráva pro logiku e-mailu (vrací data obou stran)
    const enriched = await pool.query(
      `SELECT 
         m.id, m.sender_id, m.message, m.created_at,
         p.email AS pilot_email, p.name AS pilot_name,
         a.email AS adv_email, a.name AS adv_name,
         CASE WHEN m.sender_id = c.pilot_id THEN 'pilot' ELSE 'advertiser' END AS sender_role
       FROM messages m
       JOIN conversations c ON c.id = m.conversation_id
       LEFT JOIN pilots p ON p.id = c.pilot_id
       LEFT JOIN advertisers a ON a.id = c.advertiser_id
       WHERE m.id = $1`,
      [newMessage.id]
    );
    const msg = enriched.rows[0];

    // 🔔 Naplánuj kontrolu za 1 hodinu (logika notifikací)
    setTimeout(async () => {
      try {
        if (!msg) return;

        const isPilotSender = msg.sender_role === 'pilot';
        const receiverId = isPilotSender ? msg.adv_email : msg.pilot_email;

        // Kontrola, zda příjemce zprávu neviděl
        const r = await pool.query(`
          SELECT cv.last_seen
          FROM conversation_views cv
          WHERE cv.conversation_id = $1 AND cv.user_id = $2
        `, [conversationId, isPilotSender ? advertiser_id : pilot_id]);
        
        const last_seen = r.rows[0]?.last_seen;
        const created_at = new Date(msg.created_at);
        
        // Posílej notifikaci, pokud nebyla viděna nebo je novější
        if (!last_seen || new Date(last_seen) < created_at) {
          const receiverName = isPilotSender ? msg.adv_name : msg.pilot_name;
          const senderName = isPilotSender ? msg.pilot_name : msg.adv_name;
          const subject = `💬 Nová zpráva od ${senderName}`;
          const link = 'https://www.najdipilota.cz/moje-zpravy.html';

          await transporter.sendMail({
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: receiverId,
            bcc: 'drboom@seznam.cz',
            subject: subject,
            html: wrapEmailContent(`
              <p>Dobrý den ${escapeHtml(receiverName)},</p>
              <p>máte novou zprávu od <b>${escapeHtml(senderName)}</b>.</p>
              <p style="margin:24px 0;">
                <a href="${link}"
                   style="background:#0077B6;color:#fff;text-decoration:none;
                          padding:10px 18px;border-radius:6px;font-size:14px;font-weight:500;">
                  Otevřít konverzaci
                </a>
              </p>
            `, "Nová zpráva")
          });

          console.log(`📧 Notifikace odeslána na: ${receiverId}`);
        }

      } catch (err) {
        console.error("❌ Chyba při odložené notifikaci (v2):", err);
      }
    }, 60 * 60 * 1000); // 1 hodina

    res.status(201).json({ success: true, newMessage: newMessage });

  } catch (err) {
    console.error("Chyba při odesílání zprávy:", err);
    res.status(500).json({ success: false, message: 'Chyba při odesílání zprávy' });
  }
});

app.post('/api/v2/create-conversation', async (req, res) => {
  let { pilotId, advertiserId, advertiserTable } = req.body;

  // 🧩 1️⃣ Výchozí hodnota (pokud frontend neposlal advertiserTable)
  if (!advertiserTable) advertiserTable = 'advertisers';

  try {
    // 🧠 2️⃣ Atomický insert – pokud existuje, neudělá nic
    const insertQuery = `
      INSERT INTO conversations (pilot_id, advertiser_id, advertiser_table)
      VALUES ($1, $2, $3)
      ON CONFLICT (pilot_id, advertiser_id)
      DO NOTHING
      RETURNING id, uid;
    `;

    let conversationResult = await pool.query(insertQuery, [pilotId, advertiserId, advertiserTable]);

    // 🧠 3️⃣ Pokud nebylo vloženo nic (už existuje), načteme existující
    if (conversationResult.rowCount === 0) {
      conversationResult = await pool.query(
        `SELECT id, uid FROM conversations 
         WHERE pilot_id = $1 AND advertiser_id = $2 AND advertiser_table = $3 
         LIMIT 1`,
        [pilotId, advertiserId, advertiserTable]
      );
    }

    // 🧠 4️⃣ Ověření, že jsme opravdu něco našli
    if (conversationResult.rowCount === 0) {
      console.error("⚠️ Konverzace se nepodařila vložit ani najít:", { pilotId, advertiserId, advertiserTable });
      return res.status(404).json({ success: false, message: "Konverzaci se nepodařilo vytvořit ani načíst." });
    }

    const { id: conversationId, uid: conversationUid } = conversationResult.rows[0];
    res.json({ success: true, conversationId, conversationUid });

  } catch (err) {
    console.error("❌ Chyba při vytváření konverzace:", err.message, err.code, err.detail);
    res.status(500).json({ 
      success: false, 
      message: err.message || 'Chyba serveru při vytváření konverzace' 
    });
  }
});



app.listen(PORT, () => {
  console.log(`Server běží na portu ${PORT}`);
});

// 📄 Vrátí všechny faktury
app.get('/api/invoices', requireAdminLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT i.*, p.email 
      FROM invoices i
      JOIN pilots p ON p.id = i.pilot_id
      ORDER BY i.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("Chyba při načítání faktur:", err);
    res.status(500).send("Chyba při načítání faktur.");
  }
});

// ➕ Přidá novou fakturu
app.post('/api/invoices', requireAdminLogin, async (req, res) => {
  const { pilot_id, invoice_url, amount, currency, period, type_account } = req.body;
  try {
    await pool.query(`
      INSERT INTO invoices (pilot_id, invoice_url, amount, currency, period, type_account)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [pilot_id, invoice_url, amount, currency || 'CZK', period, type_account]);
    res.send("✅ Faktura uložena.");
  } catch (err) {
    console.error("Chyba při vkládání faktury:", err);
    res.status(500).send("Nepodařilo se uložit fakturu.");
  }
});

// === Automatická záloha pilots → pilots_backup + logování + e-mail alerty ===
const EMAIL_ON_SUCCESS = false; // přepni na true, pokud chceš mít i úspěšné notifikace
const ADMIN_ALERT_EMAIL = process.env.ADMIN_ALERT_EMAIL || 'drboom@seznam.cz';

// Pomocná funkce pro časový formát (Praha)
function ts() {
  return new Date().toLocaleString('cs-CZ', { timeZone: 'Europe/Prague' });
}

// Log do DB
async function logBackup(line) {
  const msg = `[${ts()}] ${line}`;
  try {
    await pool.query('INSERT INTO backup_logs (message) VALUES ($1)', [msg]);
  } catch (e) {
    console.error('❌ [BACKUP] Chyba při zápisu do backup_logs:', e);
  }
  console.log(msg);
}

// E-mail notifikace (reuses nodemailer transporter + wrapEmailContent)
async function notifyAdmin(subject, bodyText) {
  const html = wrapEmailContent(
    `<p>${bodyText.replace(/\n/g, '<br>')}</p>`,
    'Cron záloha – NajdiPilota.cz'
  );
  try {
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: ADMIN_ALERT_EMAIL,
      subject,
      text: bodyText,
      html
    });
  } catch (e) {
    console.error('❌ [BACKUP] Nepodařilo se odeslat e-mail s notifikací:', e);
  }
}

// CRON – 1× za 5 dní ve 02:00 českého času → 00:00 UTC
// Pozn.: Render běží v UTC; 00:00 UTC ≈ 02:00 Praha
cron.schedule('0 0 */5 * *', async () => {
  await logBackup('🕒 Spouštím zálohu dat z "pilots" do "pilots_backup"...');
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query('TRUNCATE TABLE pilots_backup;');
    await client.query('INSERT INTO pilots_backup SELECT * FROM pilots;');

    const { rows: cnt } = await client.query('SELECT COUNT(*)::int AS n FROM pilots_backup;');
    const rows = cnt[0]?.n ?? 0;

    await client.query('COMMIT');
    const okMsg = `✅ Záloha úspěšná – zkopírováno ${rows} řádků.`;
    await logBackup(okMsg);

    if (EMAIL_ON_SUCCESS) {
      await notifyAdmin('[Cron] Záloha OK', `${okMsg}\nČas: ${ts()}`);
    }
  } catch (err) {
    await client.query('ROLLBACK');
    const errMsg = `❌ Chyba při záloze: ${err.message}`;
    await logBackup(errMsg);
    console.error('❌ [BACKUP ERROR]', err);

    // ✉️ e-mail jen při chybě
    await notifyAdmin('[Cron] Záloha SELHALA', `${errMsg}\nČas: ${ts()}`);
  } finally {
    client.release();
  }
});


// === CRON: 08:00 (Praha) – automatické přepnutí účtu na Free po vypršení viditelnosti ===
cron.schedule(
  '0 8 * * *',
  async () => {
    console.log('⏰ CRON 08:00: kontrola expirací účtů (auto Free) …');

    try {
      // 1️⃣ Najdeme piloty s vypršelou platností (visible_valid <= dnešní datum)
      const { rows: expiring } = await pool.query(`
        SELECT id, email, name
        FROM pilots
        WHERE visible_valid IS NOT NULL
          AND visible_valid::date <= CURRENT_DATE
          AND type_account <> 'Free'
      `);

      if (expiring.length === 0) {
        console.log('✅ Nikdo k přepnutí.');
        return;
      }

      // 2️⃣ Přepneme typ účtu na Free
      const ids = expiring.map(p => p.id);
      await pool.query(
        `UPDATE pilots SET type_account = 'Free' WHERE id = ANY($1::int[])`,
        [ids]
      );

      // 3️⃣ Pošleme každému pilotovi e-mail
      let sent = 0;
      for (const p of expiring) {
        try {
          const html = wrapEmailContent(`
            <p>Dobrý den ${escapeHtml(p.name || '')},</p>
            <p>platnost Vaší viditelnosti na <strong>NajdiPilota.cz</strong> právě vypršela. 
               Váš účet byl proto automaticky přepnut zpět na <strong>Free</strong>.</p>
            <p>Pokud chcete zůstat viditelný v mapě pilotů, můžete své členství jednoduše prodloužit
               přímo ve svém profilu</p>
            <p style="text-align:center; margin: 20px 0;">
              <a href="https://www.najdipilota.cz/login.html"
                 style="background-color:#007BFF;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;">
                 🔄 Přihlásit se a prodloužit viditelnost
              </a>
            </p>
            <p>Děkujeme, že jste součástí komunity pilotů na NajdiPilota.cz.<br>
                NajdiPilota.cz 🚁</p>
          `, 'Vaše viditelnost vypršela – účet přepnut na Free');

          await transporter.sendMail({
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: p.email,
            bcc: 'drboom@seznam.cz',
            subject: 'Vaše viditelnost vypršela – účet přepnut na Free',
            html
          });
          sent++;
        } catch (err) {
          console.error(`❌ Chyba při odesílání e-mailu pilotovi ${p.email}:`, err.message);
        }
      }

      // 4️⃣ Souhrnný e-mail adminovi
      const summary = `Přepnuto na Free: ${expiring.length} účtů.\nE-mailů pilotům odesláno: ${sent}.`;

      await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: process.env.ADMIN_ALERT_EMAIL || 'dronadmin@seznam.cz',
        bcc: 'drboom@seznam.cz',
        subject: 'Cron 08:00 – Přepnutí účtů na Free (souhrn)',
        html: wrapEmailContent(`
          <h3>Cron – Přepnutí účtů na Free</h3>
          <p>${expiring.length} pilotů přepnuto na Free.</p>
          <p>E-mailů pilotům odesláno: ${sent}.</p>
          <p>Spuštěno dne: ${new Date().toLocaleString('cs-CZ')}</p>
        `, 'Cron souhrn – Auto Free')
      });

      console.log('✅ CRON hotov:', summary);
    } catch (err) {
      console.error('❌ Chyba CRON 08:00 (auto Free):', err);
      await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: process.env.ADMIN_ALERT_EMAIL || 'dronadmin@seznam.cz',
        bcc: 'drboom@seznam.cz',
        subject: '❌ Cron 08:00 – Chyba při přepínání účtů',
        html: wrapEmailContent(`
          <p>Došlo k chybě při kontrole expirací:</p>
          <pre style="white-space:pre-wrap;">${escapeHtml(err.message)}</pre>
        `, 'Cron – chyba auto Free')
      });
    }
  },
  { timezone: 'Europe/Prague' }
);



// ──────────────────────────────────────────────────────────────
// CRON: Každý den v 08:00 odešle expirační e-maily (Europe/Prague)
// ──────────────────────────────────────────────────────────────
cron.schedule(
  '0 8 * * *',
  async () => {
    console.log('⏰ CRON: kontrola expirací členství…');

    try {
      const { rows } = await pool.query(`
        SELECT email, visible_valid::date AS valid_to,
               (visible_valid::date - CURRENT_DATE) AS days_left
        FROM pilots
        WHERE visible_valid IS NOT NULL
      `);

      for (const pilot of rows) {
        const daysLeft = Number(pilot.days_left);

        // Přeskoč, pokud není 7 nebo 3 dní
        if (![7, 3].includes(daysLeft)) continue;

        // Zkontroluj, jestli už byl e-mail poslán
        const logCheck = await pool.query(
          `SELECT 1 FROM membership_email_log 
           WHERE email = $1 AND days_left = $2 
           AND sent_at::date = CURRENT_DATE`,
          [pilot.email, daysLeft]
        );

        if (logCheck.rowCount > 0) {
          console.log(`⏭ Už odesláno dnes (${daysLeft} dní): ${pilot.email}`);
          continue;
        }
        
        // Odeslání e-mailu
const refCode = makeRefCode(pilot.id); // 🔑 stejný kód jako vrací /ref-code

if (daysLeft === 7) {
  await transporter.sendMail({
    from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
    to: pilot.email,
    subject: 'Vaše členství vyprší za 7 dní',
    html: membershipExpiry7DaysEmail(refCode)   // sem jde referral kód
  });
} else if (daysLeft === 3) {
  await transporter.sendMail({
    from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
    to: pilot.email,
    subject: 'Vaše členství vyprší za 3 dny',
    html: membershipExpiry3DaysEmail(refCode)   // sem jde referral kód
  });
} else if (daysLeft === 0) {
  await transporter.sendMail({
    from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
    to: pilot.email,
    subject: 'Vaše členství dnes vyprší',
    html: membershipExpiry0DaysEmail(refCode)
  });
}

        // Zaloguj odeslání
        await pool.query(
          `INSERT INTO membership_email_log (email, days_left) VALUES ($1, $2)`,
          [pilot.email, daysLeft]
        );

        console.log(`📧 Odesláno a zalogováno (${daysLeft} dní): ${pilot.email}`);
      }

      console.log('✅ CRON hotovo.');
    } catch (err) {
      console.error('❌ Chyba CRONu při odesílání expiračních e-mailů:', err);
    }
  },
  { timezone: 'Europe/Prague' }
);

// === PRODLOUŽENÍ ČLENSTVÍ + EMAIL ===

const accountColors = {
  'Free': '#b0f759',
  'Basic': '#258f01',   // Zelená
  'Premium': '#8f06bd'  // Fialová
};

// 1 MĚSÍC
app.get('/send-membership-email-1m', async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send("Chybí ID pilota.");

  try {
    const update = await pool.query(
      `UPDATE pilots 
        SET visible_valid = COALESCE(visible_valid, CURRENT_DATE) + INTERVAL '1 month',
            visible_payment = CURRENT_DATE
        WHERE id = $1
        RETURNING email, name, visible_valid, visible_payment, type_account`,
      [id]
    );
    if (update.rowCount === 0) return res.status(404).send("Pilot nenalezen.");
    const pilot = update.rows[0];
    const color = accountColors[pilot.type_account] || '#0077B6';

    const invoiceRes = await pool.query(
      `SELECT invoice_url FROM invoices WHERE pilot_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [id]
    );
    const invoiceLink = invoiceRes.rows[0]?.invoice_url || null;

    const content = `
      <h2 style="color:${color};">✅ Členství (${pilot.type_account}) prodlouženo o 1 měsíc</h2>
      <p>Dobrý den, ${pilot.name || ""},</p>
      <p>děkujeme, že jste si na <strong>NajdiPilota.cz</strong> prodloužil své členství.</p>
      <p><strong>Platnost nyní končí:</strong> ${new Date(pilot.visible_valid).toLocaleDateString("cs-CZ")}<br>
          <strong>Poslední platba:</strong> ${new Date(pilot.visible_payment).toLocaleDateString("cs-CZ")}</p>
      ${invoiceLink ? `<p>📎 Fakturu naleznete zde: <a href="${invoiceLink}" target="_blank">Otevřít fakturu</a></p>` : ""}
    `;
    const html = wrapEmailContent(content, `Prodloužení členství (${pilot.type_account}) o 1 měsíc`);

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: pilot.email,
      bcc: 'drboom@seznam.cz',
      subject: `Vaše členství (${pilot.type_account}) bylo prodlouženo o 1 měsíc`,
      html
    });

    res.send(`✅ Členství (1M) bylo prodlouženo a e-mail odeslán na ${pilot.email}.`);
  } catch (err) {
    console.error("❌ Chyba při prodlužování 1M:", err);
    res.status(500).send("Nepodařilo se prodloužit členství o 1M.");
  }
});

// 6 MĚSÍCŮ
app.get('/send-membership-email-6m', async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send("Chybí ID pilota.");

  try {
    const update = await pool.query(
      `UPDATE pilots 
        SET visible_valid = COALESCE(visible_valid, CURRENT_DATE) + INTERVAL '6 months',
            visible_payment = CURRENT_DATE
        WHERE id = $1
        RETURNING email, name, visible_valid, visible_payment, type_account`,
      [id]
    );
    if (update.rowCount === 0) return res.status(404).send("Pilot nenalezen.");
    const pilot = update.rows[0];
    const color = accountColors[pilot.type_account] || '#0077B6';

    const invoiceRes = await pool.query(
      `SELECT invoice_url FROM invoices WHERE pilot_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [id]
    );
    const invoiceLink = invoiceRes.rows[0]?.invoice_url || null;

    const content = `
      <h2 style="color:${color};">✅ Členství (${pilot.type_account}) prodlouženo o 6 měsíců</h2>
      <p>Dobrý den, ${pilot.name || ""},</p>
      <p>vážíme si toho, že jste si prodloužil své členství na <strong>NajdiPilota.cz</strong>.</p>
      <p><strong>Platnost nyní končí:</strong> ${new Date(pilot.visible_valid).toLocaleDateString("cs-CZ")}<br>
          <strong>Poslední platba:</strong> ${new Date(pilot.visible_payment).toLocaleDateString("cs-CZ")}</p>
      ${invoiceLink ? `<p>📎 Fakturu naleznete zde: <a href="${invoiceLink}" target="_blank">Otevřít fakturu</a></p>` : ""}
    `;
    const html = wrapEmailContent(content, `Prodloužení členství (${pilot.type_account}) o 6 měsíců`);

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: pilot.email,
      bcc: 'drboom@seznam.cz',
      subject: `Vaše členství (${pilot.type_account}) bylo prodlouženo o 6 měsíců`,
      html
    });

    res.send(`✅ Členství (6M) bylo prodlouženo a e-mail odeslán na ${pilot.email}.`);
  } catch (err) {
    console.error("❌ Chyba při prodlužování 6M:", err);
    res.status(500).send("Nepodařilo se prodloužit členství o 6M.");
  }
});


// 12 MĚSÍCŮ
app.get('/send-membership-email-12m', async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send("Chybí ID pilota.");

  try {
    const update = await pool.query(
      `UPDATE pilots 
        SET visible_valid = COALESCE(visible_valid, CURRENT_DATE) + INTERVAL '12 months',
            visible_payment = CURRENT_DATE
        WHERE id = $1
        RETURNING email, name, visible_valid, visible_payment, type_account, id`,
      [id]
    );
    if (update.rowCount === 0) return res.status(404).send("Pilot nenalezen.");
    const pilot = update.rows[0];
    const color = accountColors[pilot.type_account] || '#0077B6';

    const invoiceRes = await pool.query(
      `SELECT invoice_url FROM invoices WHERE pilot_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [id]
    );
    const invoiceLink = invoiceRes.rows[0]?.invoice_url || null;

    const content = `
      <h2 style="color:${color};">🎉 Členství (${pilot.type_account}) prodlouženo o 12 měsíců</h2>
      <p>Dobrý den, ${pilot.name || ""},</p>
      <p>děkujeme, že jste s námi! Vaše členství na <strong>NajdiPilota.cz</strong> bylo úspěšně prodlouženo.</p>
      <p><strong>Platnost nyní končí:</strong> ${new Date(pilot.visible_valid).toLocaleDateString("cs-CZ")}<br>
          <strong>Poslední platba:</strong> ${new Date(pilot.visible_payment).toLocaleDateString("cs-CZ")}</p>
      ${invoiceLink ? `<p>📎 Fakturu naleznete zde: <a href="${invoiceLink}" target="_blank">Otevřít fakturu</a></p>` : ""}
      <hr>
      <h3 style="color:#258f01;">🎁 Přiveďte kamaráda a získejte +7 dní zdarma!</h3>
      <p>Pozvěte kamaráda přes tento odkaz:</p>
      <div style="background:#f1f1f1;padding:10px;text-align:center;border-radius:6px;">
        https://www.najdipilota.cz/register.html?ref=${encodeURIComponent(pilot.id)}
      </div>
    `;
    const html = wrapEmailContent(content, `Prodloužení členství (${pilot.type_account}) o 12 měsíců`);

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: pilot.email,
      bcc: 'drboom@seznam.cz',
      subject: `Vaše členství (${pilot.type_account}) bylo prodlouženo o 12 měsíců`,
      html
    });

    res.send(`✅ Členství (12M) bylo prodlouženo a e-mail odeslán na ${pilot.email}.`);
  } catch (err) {
    console.error("❌ Chyba při prodlužování 12M:", err);
    res.status(500).send("Nepodařilo se prodloužit členství o 12M.");
  }
});


// ODESLÁNÍ E-MAILU BEZ PRODLOUŽENÍ ČLENSTVÍ
app.get('/send-email-only-1m', async (req, res) => {
  const { id } = req.query;
  if (!id) return res.status(400).send("❌ Chybí ID pilota v parametru URL.");

  try {
    // načtení dat pilota
    const result = await pool.query(
      `SELECT email, name, visible_valid, visible_payment, type_account
       FROM pilots
       WHERE id = $1`,
      [id]
    );

    if (result.rowCount === 0) return res.status(404).send("❌ Pilot nenalezen.");

    const pilot = result.rows[0];

    const content = `
      <h2 style="color:#258f01;">✅ Členství prodlouženo o 1 měsíc</h2>
      <p>Dobrý den, ${pilot.name || ""},</p>
      <p>děkujeme, že jste si na <strong>NajdiPilota.cz</strong> prodloužil své členství.</p>
      <p><strong>Platnost nyní končí:</strong> ${new Date(pilot.visible_valid).toLocaleDateString("cs-CZ")}<br>
         <strong>Poslední platba:</strong> ${new Date(pilot.visible_payment).toLocaleDateString("cs-CZ")}</p>
    `;

    const html = wrapEmailContent(content, "Prodloužení členství o 1 měsíc");

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: pilot.email,
      bcc: 'drboom@seznam.cz',
      subject: 'Vaše členství bylo prodlouženo o 1 měsíc',
      html
    });

    res.send(`📧 E-mail (1M) byl odeslán na adresu <strong>${pilot.email}</strong>.`);
  } catch (err) {
    console.error("❌ Chyba při odesílání e-mailu:", err);
    res.status(500).send("❌ Nepodařilo se odeslat e-mail.");
  }
});


// Spouští se každý den v 8:00
cron.schedule('0 8 * * *', async () => {
  console.log('📬 Denní kontrola poptávek...');

  try {
    // === 1️⃣ Připomenutí po 5 dnech ===
    const remindDays = 5;
    const { rows: reminders } = await pool.query(`
      SELECT id, title, advertiser_email, created_at
      FROM demands
      WHERE status = 'Zpracovává se'
        AND created_at < NOW() - INTERVAL '${remindDays} days'
        AND (last_reminder_at IS NULL OR last_reminder_at < NOW() - INTERVAL '${remindDays} days')
    `);

    for (const d of reminders) {
      const html = wrapEmailContent(`
        <h2>🕓 Jak to vypadá s vaší poptávkou?</h2>
        <p>Poptávka <strong>${escapeHtml(d.title)}</strong> byla zveřejněna před více než ${remindDays} dny.</p>
        <p>Pokud je již vyřešená, prosím označte ji jako <strong>Hotovo</strong> v rozhraní NajdiPilota.cz.</p>
        <p><a href="https://www.najdipilota.cz/poptavky.html"
          style="background:#0077B6;color:#fff;padding:10px 18px;text-decoration:none;border-radius:6px;">Otevřít poptávky</a></p>
      `, 'NajdiPilota.cz – Stav poptávky');

      await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: d.advertiser_email,
        subject: 'Jak to vypadá s vaší poptávkou?',
        html
      });

      await pool.query('UPDATE demands SET last_reminder_at = NOW() WHERE id = $1', [d.id]);
      console.log(`📨 Připomínka odeslána: ${d.advertiser_email}`);
    }

    // === 2️⃣ Automatické označení jako neaktivní po 30 dnech ===
    const inactiveDays = 30;
    const { rows: expired } = await pool.query(`
      UPDATE demands
      SET status = 'Neaktivní'
      WHERE status = 'Zpracovává se'
        AND created_at < NOW() - INTERVAL '${inactiveDays} days'
      RETURNING id, title, advertiser_email, created_at;
    `);

    // === 3️⃣ Odeslat přehled adminovi ===
    if (expired.length > 0) {
      const htmlList = expired
        .map(d => `<li>${escapeHtml(d.title)} – ${d.advertiser_email} (vytvořeno ${new Date(d.created_at).toLocaleDateString('cs-CZ')})</li>`)
        .join('');

      const html = wrapEmailContent(`
        <h2>🗂 Automaticky uzavřené poptávky (starší než ${inactiveDays} dní)</h2>
        <ul>${htmlList}</ul>
      `, 'NajdiPilota.cz – Uzavřené poptávky');

      await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: 'admin@najdipilota.cz',
        subject: `Uzavřené poptávky (${expired.length}) – starší než ${inactiveDays} dní`,
        html
      });

      console.log(`📋 Report odeslán administrátorovi (${expired.length} položek).`);
    } else {
      console.log('✅ Žádné poptávky k uzavření.');
    }

  } catch (err) {
    console.error('❌ Chyba při kontrole poptávek:', err);
  }
});








// ──────────────────────────────────────────────────────────────
// CRON: Denní souhrn nepřečtených zpráv (Europe/Prague) – 07:30
// ──────────────────────────────────────────────────────────────
cron.schedule(
  '30 7 * * *',
  async () => {
    console.log('⏰ CRON: denní digest nepřečtených zpráv…');
    try {
      // 1) piloti s e-mailem
      const pilotsRes = await pool.query(`
        SELECT id, email, COALESCE(NULLIF(name,''), 'Pilot') AS name
        FROM pilots
        WHERE email IS NOT NULL AND email <> ''
      `);

      for (const pilot of pilotsRes.rows) {
        // 2) vyhodnoť nepřečtené zprávy (od inzerenta) per konverzace
        const unreadRes = await pool.query(`
          SELECT 
            c.id AS conversation_id,
            a.email AS advertiser_email,
            a.name  AS advertiser_name,
            COUNT(m.*) AS unread_count,
            MAX(m.created_at) AS last_time,
            (
              SELECT m2.message
              FROM messages m2
              WHERE m2.conversation_id = c.id
                AND m2.sender_id = c.advertiser_id
                AND m2.created_at > COALESCE(cv.last_seen, '1970-01-01'::timestamp)
              ORDER BY m2.created_at DESC
              LIMIT 1
            ) AS last_message
          FROM conversations c
          JOIN advertisers a 
            ON a.id = c.advertiser_id
          LEFT JOIN conversation_views cv 
            ON cv.conversation_id = c.id AND cv.user_id = c.pilot_id  -- last_seen pro PILOTA
          JOIN messages m 
            ON m.conversation_id = c.id
           AND m.sender_id = c.advertiser_id         -- pouze zprávy od inzerenta
           AND m.created_at > COALESCE(cv.last_seen, '1970-01-01'::timestamp)
          WHERE c.pilot_id = $1
          GROUP BY c.id, a.email, a.name, cv.last_seen
          ORDER BY last_time DESC
        `, [pilot.id]);

        if (unreadRes.rowCount === 0) {
          // nic nepřečteného → nic neposíláme
          continue;
        }

        // 3) postav e-mail
        const items = unreadRes.rows.map(r => ({
          conversationId: r.conversation_id,
          advertiserEmail: r.advertiser_email,
          advertiserName: r.advertiser_name || r.advertiser_email,
          unreadCount: Number(r.unread_count),
          lastMessage: (r.last_message || '').slice(0, 300),
          lastTime: new Date(r.last_time)
        }));

        const html = buildUnreadDigestEmail(pilot.name, items);
        const text = buildUnreadDigestText(pilot.name, items);

        // 4) pošli e-mail
        await transporter.sendMail({
          from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
          to: pilot.email,
          bcc: 'drboom@seznam.cz',
          subject: `Máte ${items.reduce((a,b)=>a+b.unreadCount,0)} nepřečtených zpráv`,
          html,
          text
        });

        console.log(`📧 Digest poslán: ${pilot.email} (${items.length} vlákna)`);
      }

      console.log('✅ CRON denního digestu hotov.');
    } catch (err) {
      console.error('❌ Chyba CRONu (digest):', err);
    }
  },
  { timezone: 'Europe/Prague' }
);



// ──────────────────────────────────────────────────────────────
// CRON: Nové poptávky → 12:00 Europe/Prague → poslat Basic/Premium
// ──────────────────────────────────────────────────────────────
/*
cron.schedule(
  '0 12 * * *',
  async () => {
    console.log('⏰ [CRON] Rozesílám nové poptávky (posledních 48h)…');
    try {
      // 1) Nové veřejné poptávky za posledních 48 hodin (UTC)
      const demandsRes = await pool.query(`
        SELECT id, title, description, location, region, budget, deadline, advertiser_email, created_at
        FROM demands
        WHERE public = TRUE
          AND created_at >= NOW() - INTERVAL '48 hours'
        ORDER BY created_at DESC
      `);

      if (demandsRes.rowCount === 0) {
        console.log('ℹ️ [CRON] Žádné nové poptávky za posledních 48h → neodesílám nic.');
        return;
      }
      const demands = demandsRes.rows;

      // 2) Všichni piloti Basic / Premium s e-mailem
      const pilotsRes = await pool.query(`
        SELECT id, COALESCE(NULLIF(name,''), 'Pilot') AS name, email
        FROM pilots
        WHERE type_account IN ('Basic','Premium')
          AND email IS NOT NULL AND email <> ''
      `);

      // 3) Odeslat každému (personalizovaně)
      let success = 0;
      for (const p of pilotsRes.rows) {
        try {
          const html = buildNewDemandsDigestEmailFancy(p.name, demands);
          const text = buildNewDemandsDigestText(p.name, demands);

          await transporter.sendMail({
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: p.email,
            subject: 'Nové poptávky na NajdiPilota.cz (posledních 48 h)', // ✅ oprava
            html,
            text
          });

          success++;
          await new Promise(r => setTimeout(r, 200));
        } catch (e) {
          console.error(`❌ [CRON] Nepodařilo se poslat ${p.email}:`, e.message);
        }
      }

      console.log(`✅ [CRON] Rozesláno ${success}/${pilotsRes.rowCount} pilotům.`);
    } catch (err) {
      console.error('❌ [CRON] Chyba rozesílky nových poptávek:', err);
    }
  },
  { timezone: 'Europe/Prague' }
);
*/




// Testovací SKRIPTA

// Testovací endpoint pro expirační e-mail
app.get('/test-expiry-email', async (req, res) => {
  const { email, days } = req.query;
  if (!email || !days) {
    return res.status(400).send("Použij ?email=...&days=7, 3 nebo 0");
  }

  try {
    let subject, html, text;

    if (days === '7') {
      subject = "Test: Vaše členství vyprší za 7 dní";
      html = membershipExpiry7DaysEmail("Testovací Pilot");
      text = "Testovací text – členství vyprší za 7 dní";
    } else if (days === '3') {
      subject = "Test: Vaše členství vyprší za 3 dny";
      html = membershipExpiry3DaysEmail("Testovací Pilot");
      text = "Testovací text – členství vyprší za 3 dny";
    } else if (days === '0') {
      subject = "Test: Vaše členství dnes vyprší";
      html = membershipExpiry0DaysEmail("Testovací Pilot");
      text = "Testovací text – členství vyprší dnes";
    } else {
      return res.status(400).send("days musí být 7, 3 nebo 0");
    }

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: email,
      subject,
      html,
      text
    });

    res.send(`📨 Testovací expirační e-mail (${days} dní) poslán na ${email}`);
  } catch (err) {
    console.error("Chyba v /test-expiry-email:", err);
    res.status(500).send("Nepodařilo se odeslat testovací mail");
  }
});



// Testovací endpoint pro okamžité odeslání digestu
app.get('/test-digest', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).send("Chybí email pilota");

  try {
    // Najdi pilota
    const pilotRes = await pool.query(
      'SELECT id, name, email FROM pilots WHERE LOWER(email) = LOWER($1)',
      [email]
    );
    if (pilotRes.rowCount === 0) {
      return res.status(404).send("Pilot nenalezen");
    }
    const pilot = pilotRes.rows[0];

    // Nepřečtené zprávy
    const unreadRes = await pool.query(`
      WITH last_msgs AS (
        SELECT DISTINCT ON (c.advertiser_id)
               c.advertiser_id,
               m.message    AS lastMessage,
               m.created_at AS lastTime
        FROM messages m
        JOIN conversations c ON c.id = m.conversation_id
        WHERE c.pilot_id = $1
          AND m.sender_id = c.advertiser_id
        ORDER BY c.advertiser_id, m.created_at DESC
      ),
      unread_counts AS (
        SELECT a.id AS advertiser_id,
               COUNT(*) AS unreadCount
        FROM messages m
        JOIN conversations c ON c.id = m.conversation_id
        JOIN advertisers a ON a.id = c.advertiser_id
        LEFT JOIN conversation_views cv
          ON cv.conversation_id = c.id AND cv.user_id = c.pilot_id
        WHERE c.pilot_id = $1
          AND m.sender_id = c.advertiser_id
          AND m.created_at > COALESCE(cv.last_seen, '1970-01-01'::timestamp)
        GROUP BY a.id
      )
      SELECT a.name  AS advertiserName,
             a.email AS advertiserEmail,
             uc.unreadCount,
             lm.lastMessage,
             lm.lastTime
      FROM unread_counts uc
      JOIN advertisers a ON a.id = uc.advertiser_id
      LEFT JOIN last_msgs lm ON lm.advertiser_id = uc.advertiser_id
      ORDER BY lm.lastTime DESC NULLS LAST;
    `, [pilot.id]);

    if (unreadRes.rowCount === 0) {
      return res.send("✅ Žádné nepřečtené zprávy – e-mail se neposlal.");
    }

    const items = unreadRes.rows.map(r => ({
      advertiserName: r.advertisername,
      advertiserEmail: r.advertiseremail,
      unreadCount: r.unreadcount,
      lastMessage: r.lastmessage,
      lastTime: r.lasttime
    }));

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: pilot.email,
      subject: "Souhrn nepřečtených zpráv – testovací odeslání",
      html: buildUnreadDigestEmail(pilot.name, items),
      text: buildUnreadDigestText(pilot.name, items)
    });

    res.send(`📨 Digest byl odeslán na ${pilot.email} (${items.length} konverzací).`);
  } catch (err) {
    console.error("Chyba v /test-digest:", err);
    res.status(500).send("Chyba při odesílání digestu");
  }
});




// ---------------------------------------------------------------------
// Jednotný wrapper pro všechny e-maily
// ---------------------------------------------------------------------
function wrapEmailContent(innerHtml, title = "NajdiPilota.cz") {
  return `
<div style="font-family:'Poppins','Segoe UI',sans-serif;background:#F8F9FA;padding:0;margin:0;">
  <!-- Header -->
  <div style="background:#0077B6;color:#fff;padding:16px 20px;text-align:center;">
    <h1 style="margin:0;font-size:20px;font-weight:600;">${title}</h1>
  </div>

  <!-- Content -->
  <div style="background:#fff;padding:20px;color:#495057;font-size:15px;line-height:1.6;">
    ${innerHtml}
  </div>

  <!-- Footer -->
  <div style="background:#F1F1F1;color:#6c757d;font-size:12px;padding:12px;text-align:center;">
    © 2025 NajdiPilota.cz – Automatická notifikace
  </div>
</div>`;
}

// ---------------------------------------------------------------------
// Onboarding e-mail – zachovány všechny barvy účtů
// ---------------------------------------------------------------------

function onboardingEmailContent() {
  const content = `
  <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f4f7fa" style="padding:30px 0;">
    <tr>
      <td align="center">

        <table width="600" cellpadding="0" cellspacing="0" bgcolor="#ffffff" 
               style="border-radius:10px;overflow:hidden;box-shadow:0 4px 18px rgba(0,0,0,0.08);">

          <!-- LOGO + HEADER -->
          <tr>
            <td align="center" style="padding:25px 20px 0;background:#ffffff;">
              <img src="cid:logoNP" alt="NajdiPilota.cz" 
                   style="height:80px;display:block;margin-bottom:12px;">
              <div style="font-size:19px;color:#0077B6;font-weight:600;margin-bottom:10px;">
                Vítejte na NajdiPilota.cz!
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:0 40px;">
              <hr style="border:none;border-top:1px solid #e0e6ed;margin:20px 0;" />
            </td>
          </tr>

          <!-- MAIN CONTENT -->
          <tr>
            <td style="padding:0 40px 20px;color:#495057;font-size:15px;line-height:1.6;">

              <p>Děkujeme, že jste se zaregistrovali na 
                 <strong style="color:#0077B6;">NajdiPilota.cz</strong>! 
                 Jsme rádi, že se připojujete k naší komunitě profesionálních pilotů dronů.</p>

              <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Jak začít?</h2>
              <ul style="padding-left:20px;">
                <li><strong>Dokončete svůj profil:</strong> Aktuální údaje pomohou klientům vás snadněji najít.</li>
                <li><strong>Zůstaňte viditelní:</strong> Aktivujte viditelnost účtu a nabídněte své služby.</li>
                <li><strong>Využijte nabídky:</strong> Jako pilot získáte přístup k exkluzivním akcím a slevám.</li>
              </ul>

              <h2 style="color:#0077B6;font-size:17px;margin-top:25px;">Váš aktuální účet</h2>

              <p>Váš účet je nastaven na typ 
                 <strong style="color:#258f01;">Basic</strong>, což přináší tyto výhody:</p>

              <ul style="padding-left:20px;">
                <li><span style="color:#258f01;font-weight:600;">Viditelnost:</span> Vaše jméno a status jsou dostupné inzerentům.</li>
                <li><span style="color:#258f01;font-weight:600;">2 drony a 2 specializace:</span> Flexibilní nabídka služeb.</li>
                <li><span style="color:#258f01;font-weight:600;">Dostupnost a dojezd:</span> Klienti vidí, kdy a kde můžete pracovat.</li>
                <li><span style="color:#258f01;font-weight:600;">Ověřený provozovatel:</span> Vyšší důvěryhodnost a více zakázek.</li>
              </ul>

              <h2 style="color:#0077B6;font-size:17px;margin-top:25px;">Co nabízí Premium?</h2>

              <p>Pokud chcete plný přístup ke všem funkcím, 
                 <strong style="color:#8f06bd;">Premium účet</strong> je pro vás ideální:</p>

              <ul style="padding-left:20px;">
                <li><span style="color:#8f06bd;font-weight:600;">Neomezeně dronů a až 10 specializací</span></li>
                <li><span style="color:#8f06bd;font-weight:600;">Viditelné kontakty:</span> E-mail i telefon viditelné inzerentům.</li>
                <li><span style="color:#8f06bd;font-weight:600;">Fialová značka na mapě:</span> výrazné zvýraznění vašeho profilu.</li>
                <li><span style="color:#8f06bd;font-weight:600;">Přímá komunikace:</span> inzerenti vás mohou oslovit napřímo.</li>
              </ul>

              <h2 style="color:#0077B6;font-size:17px;margin-top:25px;">Pokud členství vyprší</h2>

              <p>Po vypršení členství se váš účet změní na 
                 <strong style="color:#b0f759;">Free</strong> s omezeními:</p>

              <ul style="padding-left:20px;">
                <li>Pouze základní informace (jméno, 1 dron, 1 specializace)</li>
                <li>Bez přístupu ke kontaktům a rozšířeným funkcím</li>
              </ul>

              <p>Členství můžete kdykoliv prodloužit v nastavení profilu.  
                 Navíc můžete sdílet svůj referral kód – získáte 7 dní Basic zdarma nebo Premium navíc.</p>

              <h2 style="color:#0077B6;font-size:17px;margin-top:25px;">Co dál?</h2>
              <p>Začněte aktivně spravovat svůj profil a přitahujte více inzerentů.  
                 Pokud chcete růst ještě rychleji, zvažte 
                 <strong style="color:#8f06bd;">přechod na Premium účet</strong>.</p>

              <p>V případě dotazů pište na 
                 <a href="mailto:dronadmin@seznam.cz" style="color:#0077B6;">dronadmin@seznam.cz</a>.</p>

              <p style="margin-top:30px;">S pozdravem,<br><strong>Tým NajdiPilota.cz</strong></p>

              <p style="font-size:13px;color:#6c757d;">Více informací najdete na stránkách 
                <a href="https://www.najdipilota.cz/o-projektu.html" style="color:#0077B6;">O projektu</a> 
                a <a href="https://www.najdipilota.cz/faq.html" style="color:#0077B6;">FAQ</a>.
              </p>

            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td style="padding:20px 40px 30px;color:#6c757d;font-size:12px;text-align:center;">
              Tento e-mail byl odeslán z platformy <strong>NajdiPilota.cz</strong>.
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
  `;

  return wrapEmailContent(content, "Vítejte na NajdiPilota.cz!");
}

// ---------------------------------------------------------------------
// E-mail po smazání účtu – zachován jednotný styl a barvy
// ---------------------------------------------------------------------
function deleteAccountEmailContent(name = "") {
  const content = `
    <table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f4f7fa" style="padding:30px 0;">
      <tr>
        <td align="center">
          <table width="600" cellpadding="0" cellspacing="0" bgcolor="#ffffff" 
                 style="border-radius:10px;overflow:hidden;box-shadow:0 4px 18px rgba(0,0,0,0.08);">

            <!-- LOGO + HEADER -->
            <tr>
              <td align="center" style="padding:25px 20px 0;background:#ffffff;">
                <img src="cid:logoNP" alt="NajdiPilota.cz" 
                     style="height:80px;display:block;margin-bottom:12px;">
                <div style="font-size:19px;color:#0077B6;font-weight:600;margin-bottom:10px;">
                  Účet byl smazán
                </div>
              </td>
            </tr>

            <tr><td style="padding:0 40px;">
              <hr style="border:none;border-top:1px solid #e0e6ed;margin:20px 0;" />
            </td></tr>

            <!-- MAIN CONTENT -->
            <tr>
              <td style="padding:0 40px 20px;color:#495057;font-size:15px;line-height:1.6;">

                <p>Dobrý den${name ? `, <strong>${name}</strong>` : ""},</p>

                <p>potvrzujeme, že váš účet na 
                <strong style="color:#0077B6;">NajdiPilota.cz</strong> byl úspěšně smazán.</p>

                <p>Je nám líto, že odcházíte – vždy jsme se snažili poskytovat co nejlepší prostředí
                pro profesionální piloty i začátečníky. Pokud k tomu máte chvilku, budeme rádi za jakoukoliv zpětnou vazbu,
                která nám pomůže platformu vylepšit.</p>

                <h2 style="color:#0077B6;font-size:17px;margin-top:25px;">Co bylo odstraněno?</h2>
                <ul style="padding-left:20px;">
                  <li>Účet uživatele a všechny osobní údaje</li>
                  <li>Veškeré veřejné informace o profilu</li>
                  <li>Zprávy, konverzace a historie komunikace</li>
                  <li>GDPR souhlasy vázané na váš účet</li>
                </ul>

                <p style="margin-top:20px;">
                  Pokud byste si to někdy rozmysleli, <strong style="color:#0077B6;">jste kdykoliv vítáni zpět</strong>.
                  Registrace je opět otázkou jedné minuty.
                </p>

                <p style="margin-top:30px;">S pozdravem,<br>
                <strong>Tým NajdiPilota.cz</strong></p>

              </td>
            </tr>

            <!-- FOOTER -->
            <tr>
              <td style="padding:20px 40px 30px;color:#6c757d;font-size:12px;text-align:center;">
                Tento e-mail byl odeslán z platformy <strong>NajdiPilota.cz</strong>.
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  `;

  return wrapEmailContent(content, "Účet byl smazán");
}



/*
function onboardingEmailContent() {
  const content = `
    <p>Děkujeme, že jste se zaregistrovali na 
       <strong style="color:#0077B6;">NajdiPilota.cz</strong>! 
       Jsme rádi, že se připojujete k naší komunitě profesionálních pilotů dronů.</p>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Jak začít?</h2>
    <ul style="padding-left:20px;">
      <li><strong>Dokončete svůj profil:</strong> Aktuální údaje pomohou klientům vás snadněji najít.</li>
      <li><strong>Zůstaňte viditelní:</strong> Aktivujte viditelnost účtu a nabídněte své služby.</li>
      <li><strong>Využijte nabídky:</strong> Jako pilot získáte přístup k exkluzivním akcím a slevám.</li>
    </ul>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Váš aktuální účet</h2>
    <p>Váš účet je nastaven na typ <strong style="color:#258f01;">Basic</strong>, což přináší tyto výhody:</p>
    <ul style="padding-left:20px;">
      <li><span style="color:#258f01;font-weight:600;">Viditelnost:</span> Vaše jméno a status jsou dostupné inzerentům.</li>
      <li><span style="color:#258f01;font-weight:600;">2 drony a 2 specializace:</span> Flexibilní nabídka služeb.</li>
      <li><span style="color:#258f01;font-weight:600;">Dostupnost a dojezd:</span> Klienti vidí, kdy a kde můžete pracovat.</li>
      <li><span style="color:#258f01;font-weight:600;">Ověřený provozovatel:</span> Vyšší důvěryhodnost a více zakázek.</li>
    </ul>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Co nabízí Premium?</h2>
    <p>Pokud chcete plný přístup ke všem funkcím, 
       <strong style="color:#8f06bd;">Premium účet</strong> je pro vás ideální:</p>
    <ul style="padding-left:20px;">
      <li><span style="color:#8f06bd;font-weight:600;">Neomezený počet dronů a specializací</span></li>
      <li><span style="color:#8f06bd;font-weight:600;">Viditelné kontakty:</span> E-mail i telefon viditelné inzerentům.</li>
      <li><span style="color:#8f06bd;font-weight:600;">Fialová značka na mapě:</span> výrazné zvýraznění vašeho profilu.</li>
      <li><span style="color:#8f06bd;font-weight:600;">Přímá komunikace:</span> inzerenti vás mohou oslovit napřímo.</li>
    </ul>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Pokud členství vyprší</h2>
    <p>Po vypršení členství se váš účet změní na 
       <strong style="color:#b0f759;">Free</strong> s omezeními:</p>
    <ul style="padding-left:20px;">
      <li>Pouze základní informace (jméno, 1 dron, 1 specializace)</li>
      <li>Bez přístupu ke kontaktům a rozšířeným funkcím</li>
    </ul>

    <p>Členství můžete kdykoliv prodloužit v nastavení profilu.  
       Navíc můžete sdílet svůj referral kód – získáte 7 dní Basic zdarma nebo Premium navíc.</p>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Co dál?</h2>
    <p>Začněte aktivně spravovat svůj profil a přitahujte více inzerentů.  
       Pokud chcete růst ještě rychleji, zvažte 
       <strong style="color:#8f06bd;">přechod na Premium účet</strong>.</p>

    <p>V případě dotazů pište na 
       <a href="mailto:dronadmin@seznam.cz" style="color:#0077B6;">dronadmin@seznam.cz</a>.</p>

    <p style="margin-top:30px;">S pozdravem,<br><strong>Tým NajdiPilota.cz</strong></p>

    <p style="font-size:13px;color:#6c757d;">Více informací najdete na stránkách 
      <a href="https://www.najdipilota.cz/o-projektu.html" style="color:#0077B6;">O projektu</a> 
      a <a href="https://www.najdipilota.cz/faq.html" style="color:#0077B6;">FAQ</a>.
    </p>
  `;
  return wrapEmailContent(content, "Vítejte na NajdiPilota.cz!");
}
*/

// ---------------------------------------------------------------------
// Upomínka – 7 dní do vypršení
// ---------------------------------------------------------------------
function membershipExpiry7DaysEmail(refCode) {
  const refUrl = `https://najdipilota.cz/register.html?ref=${encodeURIComponent(refCode)}`;
  const content = `
    <h2 style="color:#0077B6;">⏳ Vaše členství brzy vyprší</h2>
    <p>Zbývá už jen <strong>7 dní</strong> do vypršení platnosti vašeho členství.</p>
    <p><strong>Jak prodloužit členství?</strong></p>
    <ol>
      <li>Přihlaste se na svůj účet pilota.</li>
      <li>V profilu klikněte na <strong>"Prodloužit členství"</strong>.</li>
    </ol>
    <p><a href="https://www.najdipilota.cz/login.html" style="color:#0077B6;">Přihlašte se a prodlužte členství</a></p>
    <hr>
    <h3 style="color:#258f01;">🎁 Přiveďte kamarád a získejte +7 dní zdarma!</h3>
    <p>Pozvěte kamaráda přes tento odkaz:</p>
    <div style="background:#f1f1f1;padding:10px;text-align:center;border-radius:6px;">${refUrl}</div>
  `;
  return wrapEmailContent(content, "Upomínka členství");
}

// ---------------------------------------------------------------------
// Upomínka – 3 dny do vypršení
// ---------------------------------------------------------------------
function membershipExpiry3DaysEmail(refCode) {
  const refUrl = `https://najdipilota.cz/register.html?ref=${encodeURIComponent(refCode)}`;
  const content = `
    <h2 style="color:red;">⚠️ Poslední 3 dny pro prodloužení!</h2>
    <p>Vaše členství vyprší už za <strong>3 dny</strong>. Poté bude účet převeden na 
       <strong style="color:#b0f759;">Free</strong>.</p>
    <p><a href="https://www.najdipilota.cz/login.html" style="color:#0077B6;">Přihlašte se a prodlužte členství</a></p>
    <hr>
    <h3 style="color:#258f01;">🎁 Přiveďte kamarád a získejte +7 dní zdarma!</h3>
    <div style="background:#f1f1f1;padding:10px;text-align:center;border-radius:6px;">${refUrl}</div>
  `;
  return wrapEmailContent(content, "Upomínka členství");
}

// ---------------------------------------------------------------------
// Upomínka – 0 dny do vypršení
// ---------------------------------------------------------------------
function membershipExpiry0DaysEmail(refCode) {
  const refUrl = `https://najdipilota.cz/register.html?ref=${encodeURIComponent(refCode)}`;
  const content = `
    <h2 style="color:red;">⚠️ Členství vyprší dnes!</h2>
    <p>Vaše členství vyprší <strong>dnes</strong>. Pokud si jej neprodloužíte,
       účet bude převeden na <strong style="color:#b0f759;">Free</strong>.</p>
    <p><a href="https://www.najdipilota.cz/login.html" style="color:#0077B6;">Přihlašte se a prodlužte členství</a></p>
    <hr>
    <h3 style="color:#258f01;">🎁 Přiveďte kamarád a získejte +7 dní zdarma!</h3>
    <div style="background:#f1f1f1;padding:10px;text-align:center;border-radius:6px;">${refUrl}</div>
  `;
  return wrapEmailContent(content, "Upomínka členství");
}

// ---------------------------------------------------------------------
// E-mail při vypršení viditelnosti – přepnutí účtu na Free
// ---------------------------------------------------------------------
function expiredMembershipEmailContent(name) {
  const content = `
    <p>Dobrý den ${escapeHtml(name || '')},</p>

    <p>Vaše platnost na 
       <strong style="color:#0077B6;">NajdiPilota.cz</strong> právě vypršela. 
       Váš účet byl automaticky přepnut na typ 
       <strong style="color:#b0f759;">Free</strong>.</p>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Co to znamená?</h2>
    <ul style="padding-left:20px;">
      <li><strong style="color:#b0f759;">Free účet</strong> má omezenou viditelnost v mapě a inzerenti nevidí vaše kontaktní údaje.</li>
      <li>Můžete nadále spravovat svůj profil a aktualizovat data.</li>
      <li>K plné viditelnosti a kontaktům se můžete vrátit kdykoliv – prodloužením členství.</li>
    </ul>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Jak zvýšit viditelnost?</h2>
    <p>Pro prodloužení navštivte 
      <a href="https://www.najdipilota.cz/subscription.html" style="color:#0077B6;text-decoration:none;font-weight:600;">Možnosti členství a jejich výhody</a> 
      nebo se přihlašte do vašeho účtu níže:</p>

    <p style="text-align:center; margin: 25px 0;">
      <a href="https://www.najdipilota.cz/login.html" 
         style="background-color:#0077B6;color:#fff;padding:12px 20px;border-radius:6px;
                text-decoration:none;font-size:16px;">
        🔄 Přihlásit se a prodloužit viditelnost
      </a>
    </p>

    <h2 style="color:#0077B6;font-size:17px;margin-top:20px;">Proč zůstat viditelný?</h2>
    <ul style="padding-left:20px;">
      <li><strong style="color:#258f01;">Basic účet</strong> – zelená značka v mapě, kontakt viditelný inzerentům.</li>
      <li><strong style="color:#8f06bd;">Premium účet</strong> – fialová značka, až 10 specializací, přímé kontakty a prioritní notofikace od inzerentů.</li>
      <li>Více zakázek, více zobrazení, vyšší důvěra u klientů.</li>
    </ul>

    <p style="margin-top:30px;">Děkujeme, že jste součástí komunity pilotů! 🚁<br>
       <strong>Tým NajdiPilota.cz</strong></p>

    <p style="font-size:13px;color:#6c757d;">Více informací naleznete na stránkách 
      <a href="https://www.najdipilota.cz/o-projektu.html" style="color:#0077B6;">O projektu</a> 
      a <a href="https://www.najdipilota.cz/faq.html" style="color:#0077B6;">FAQ</a>.
    </p>
  `;
  return wrapEmailContent(content, "Vaše viditelnost vypršela – účet přepnut na Free");
}


// ---------------------------------------------------------------------
// Přehled nepřečtených zpráv
// ---------------------------------------------------------------------
function buildUnreadDigestEmail(pilotName, items) {
  const rows = items.map(it => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #eee;">
        <strong>${escapeHtml(it.advertiserName)}</strong><br>
        <span style="font-size:12px;color:#666;">${escapeHtml(it.advertiserEmail)}</span>
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:center;">
        ${it.unreadCount}
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #eee;">
        ${escapeHtml(it.lastMessage)}<br>
        <span style="font-size:12px;color:#666;">${it.lastTime.toLocaleString('cs-CZ')}</span>
      </td>
    </tr>
  `).join('');

  const total = items.reduce((a,b)=>a+b.unreadCount,0);

  const content = `
    <p>Dobrý den, <strong>${escapeHtml(pilotName)}</strong> 👋</p>
    <p>Máte <strong>${total}</strong> nepřečtených zpráv.</p>
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <thead>
        <tr style="background:#ecf0f1;">
          <th style="padding:8px;text-align:left;">Inzerent</th>
          <th style="padding:8px;">Počet</th>
          <th style="padding:8px;text-align:left;">Poslední zpráva</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    <p style="margin-top:20px;">
      <a href="https://www.najdipilota.cz/login.html" style="color:#0077B6;">👉 Přihlaš se a otevři nepřečtené zprávy</a>
    </p>
  `;
  return wrapEmailContent(content, "Nepřečtené zprávy");
}

// ---------------------------------------------------------------------
// Přehled nových poptávek
// ---------------------------------------------------------------------
function buildNewDemandsDigestEmailFancy(pilotName, demands) {
  const rows = demands.map(d => `
    <tr>
      <td style="padding:12px;border-bottom:1px solid #eee;">
        <strong>${escapeHtml(d.title || 'Bez názvu')}</strong><br>
        <span style="font-size:13px;color:#7f8c8d;">${escapeHtml(d.location || d.region || '')}</span><br>
        <span style="font-size:14px;color:#34495e;">${(d.description || '').slice(0, 160)}${(d.description || '').length > 160 ? '…' : ''}</span>
      </td>
      <td style="padding:12px;border-bottom:1px solid #eee;text-align:right;font-weight:bold;color:#27ae60;">
        ${d.budget != null ? (d.budget + ' Kč') : '—'}
      </td>
    </tr>
  `).join('');

  const content = `
    <p>Dobrý den, <strong>${escapeHtml(pilotName || 'pilote')}</strong> 👋</p>
    <p>Přinášíme vám nové poptávky z posledních 48 hodin:</p>
    <table style="width:100%;border-collapse:collapse;font-size:14px;">
      <thead>
        <tr style="background:#ecf0f1;">
          <th style="padding:12px;text-align:left;">Poptávka</th>
          <th style="padding:12px;text-align:right;">Rozpočet</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    <div style="text-align:center;margin-top:24px;">
      <a href="https://www.najdipilota.cz/login.html" 
         style="background:#27ae60;color:#fff;text-decoration:none;padding:12px 20px;border-radius:6px;font-weight:bold;">
        👉 Přihlaš se a zobraz všechny poptávky
      </a>
    </div>
  `;
  return wrapEmailContent(content, "Nové poptávky");
}

// ---------------------------------------------------------------------
// Nová poptávka přidána – zachovány všechny barvy účtů
// ---------------------------------------------------------------------

function buildNewDemandAlertEmail(pilotName, demand) {
  return wrapEmailContent(`
    <p>Dobrý den ${pilotName},</p>
    <p>Na <strong style="color:#0077B6;">NajdiPilota.cz</strong> byla právě vložena nová poptávka:</p>
    <ul>
      <li><strong>${escapeHtml(demand.title)}</strong></li>
      <li>Lokalita: ${escapeHtml(demand.location)}${demand.region ? ', ' + escapeHtml(demand.region) : ''}</li>
      ${demand.budget ? `<li>Rozpočet: ${demand.budget === 'dohodou' ? 'Dohodou' : demand.budget + ' Kč'}</li>` : ''}
      ${demand.deadline ? `<li>Termín: ${demand.deadline}</li>` : ''}
    </ul>
    <p>
      <a href="https://www.najdipilota.cz/login.html"
         style="background:#0077B6;color:#fff;text-decoration:none;padding:10px 18px;
                border-radius:6px;font-size:14px;font-weight:500;">
        Přihlašte se a zobrazte poptávku
      </a>
    </p>
    <p style="color:#8f06bd;font-weight:600;margin-top:25px;">
      Toto upozornění se odesílá pouze účtům Premium
    </p>
    <p style="margin-top:30px;">S pozdravem,<br><strong>Tým NajdiPilota.cz</strong></p>
  `, "Nová poptávka na NajdiPilota.cz");
}

// ──────────────────────────────────────────────────────────────
// CRON: Každé 2 dny ve 08:00 (Praha) kontroluje GPS a odesílá e-maily
// ──────────────────────────────────────────────────────────────
cron.schedule(
  '0 8 */2 * *',
  async () => {
    console.log('⏰ CRON: kontrola pilotů bez GPS souřadnic...');
    try {
      const { rows: pilots } = await pool.query(`
        SELECT id, email, name, latitude, longitude
        FROM pilots
        WHERE id < 10000 AND (latitude IS NULL OR longitude IS NULL)
          AND email IS NOT NULL
      `);

      if (pilots.length === 0) {
        console.log('✅ Žádní piloti bez GPS souřadnic.');
        return;
      }

      let sentCount = 0;
      for (const pilot of pilots) {
        try {
          await transporter.sendMail({
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: pilot.email,
            bcc: 'drboom@seznam.cz',
            subject: "Upozornění: GPS v profilu není správně nastavena",
            html: gpsFixEmailContent()
          });
          sentCount++;
          console.log(`📧 Odeslán GPS fix e-mail na: ${pilot.email}`);
        } catch (mailError) {
          console.error(`❌ Chyba při odesílání e-mailu na ${pilot.email}:`, mailError);
        }
      }

      console.log(`✅ CRON hotovo. E-mail odeslán ${sentCount} pilotům.`);
    } catch (dbError) {
      console.error('❌ Chyba CRONu při kontrole pilotů (DB):', dbError);
    }
  },
  { timezone: 'Europe/Prague' }
);


// ──────────────────────────────────────────────────────────────
// === CRON: 08:00 (Praha) – přepnutí na Free + e-maily ===
// ──────────────────────────────────────────────────────────────
cron.schedule(
  '0 8 * * *',
  async () => {
    console.log('⏰ CRON 08:00: kontrola expirací účtů …');
    try {
      const { rows: expiring } = await pool.query(`
        SELECT id, email, name
        FROM pilots
        WHERE visible_valid IS NOT NULL
          AND visible_valid::date <= CURRENT_DATE
          AND type_account <> 'Free'
      `);

      if (expiring.length === 0) {
        console.log('✅ Nikdo k přepnutí.');
        return;
      }

      const ids = expiring.map(r => r.id);
      await pool.query(
        `UPDATE pilots SET type_account = 'Free' WHERE id = ANY($1::int[])`,
        [ids]
      );

      let sent = 0;
      for (const p of expiring) {
        try {
          await transporter.sendMail({
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: p.email,
            bcc: 'drboom@seznam.cz',
            subject: 'Vaše viditelnost vypršela – účet přepnut na Free',
            html: expiredMembershipEmailContent(p.name)
          });
          sent++;
        } catch (err) {
          console.error(`❌ E-mail pilotovi ${p.email} selhal:`, err.message);
        }
      }

      // souhrnný report
      const summaryHtml = wrapEmailContent(`
        <h3>Cron 08:00 – Přepnutí účtů na Free</h3>
        <p>Pilotů přepnuto: <strong>${expiring.length}</strong></p>
        <p>E-mailů odesláno: <strong>${sent}</strong></p>
        <p>Datum: ${new Date().toLocaleString('cs-CZ')}</p>
      `, 'Cron souhrn – Auto Free');

      await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: 'drboom@seznam.cz',
        subject: 'Cron – Přepnutí účtů na Free (souhrn)',
        html: summaryHtml
      });

      console.log(`✅ Cron hotov: ${sent}/${expiring.length} e-mailů odesláno.`);
    } catch (err) {
      console.error('❌ Chyba CRON 08:00:', err);
    }
  },
  { timezone: 'Europe/Prague' }
);


// ---------------------------------------------------------------------
// GPS fix e-mail
// ---------------------------------------------------------------------
function gpsFixEmailContent() {
  const content = `
    <p>Dobrý den,</p>
    <p>ve Vašem profilu na <strong style="color:#0077B6;">NajdiPilota.cz</strong> 
       chybí správné GPS souřadnice. Díky nim se zobrazíte na mapě a inzerenti vás snáz najdou.</p>

    <p>Pro správné zobrazení prosím doplňte nebo opravte svou adresu v účtu:</p>

    <p style="margin:24px 0;">
      <a href="https://www.najdipilota.cz/login.html"
         style="background:#0077B6;color:#fff;text-decoration:none;
                padding:10px 18px;border-radius:6px;font-size:14px;font-weight:500;">
        Přihlásit se do účtu
      </a>
    </p>

    <p style="margin-top:30px;">S pozdravem,<br>
       <strong>Tým NajdiPilota.cz</strong></p>
  `;
  return wrapEmailContent(content, "GPS nastavení");
}



// ---------------------------------------------------------------------
// Endpoint: Odeslání GPS fix e-mailu
// ---------------------------------------------------------------------
app.post('/send-gps-fix-email', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("❌ Chybí e-mail.");

  try {
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to: email,
      bcc: 'drboom@seznam.cz',   // 📌 skrytá kopie pro admina
      subject: "Upozornění: GPS v profilu není správně nastavena",
      html: gpsFixEmailContent() // využití vaší funkce s jednotným designem
    });

    res.send("✅ E-mail o GPS nastavení odeslán.");
  } catch (err) {
    console.error("❌ Chyba při odesílání GPS e-mailu:", err);
    res.status(500).send("Chyba při odesílání e-mailu.");
  }
});


// ⬇️ TEST: pošli všechny e-maily na jednu adresu (jen z localhostu)
app.get('/test-send-all-emails', allowLocalhostOnly, async (req, res) => {
  const to = req.query.to || 'drboom@seznam.cz';

  // vzorová data pro digesty/demands
  const sampleUnreadItems = [
    {
      advertiserName: 'Acme s.r.o.',
      advertiserEmail: 'poptavky@acme.cz',
      unreadCount: 2,
      lastMessage: 'Dobrý den, posíláme upřesnění lokality a termínu…',
      lastTime: new Date()
    },
    {
      advertiserName: 'FotoDrone',
      advertiserEmail: 'kontakt@fotodrone.cz',
      unreadCount: 1,
      lastMessage: 'Měli bychom zájem o letecké snímky vinic.',
      lastTime: new Date(Date.now() - 3600 * 1000)
    }
  ];

  const sampleDemands = [
    {
      title: 'Mapování stavby – Praha 6',
      description: 'Jednorázový let, ortofoto + pár fotek detailů.',
      location: 'Praha 6',
      region: 'Praha',
      budget: 6000,
      deadline: null,
      advertiser_email: 'stavby@invest.cz',
      created_at: new Date()
    },
    {
      title: 'Svatba – krátké video z dronu',
      description: 'Sobota od 14:00, cca 30–45 min záběrů.',
      location: 'Brno',
      region: 'Jihomoravský',
      budget: 4500,
      deadline: null,
      advertiser_email: 'nevesty@love.cz',
      created_at: new Date(Date.now() - 6 * 3600 * 1000)
    }
  ];

  const refCode = 'TEST-ABC123';

  const wrapIfPossible = (inner, title) => {
    try {
      if (typeof wrapEmailContent === 'function') {
        return wrapEmailContent(inner, title);
      }
    } catch {}
    return inner;
  };

  const results = [];
  try {
    
    // 1) Onboarding
await transporter.sendMail({
  from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
  to, 
  subject: "Vítejte na NajdiPilota.cz!",
  html: onboardingEmailContent(),
  attachments: [
  {
    filename: "logo.png",
    path: path.join(__dirname, "public", "icons", "logo.png"),
    cid: "logoNP"
  }
]

});


    results.push('✅ Onboarding odeslán');

    // 2) Expirace 7 dní
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to,
      subject: 'TEST: Členství vyprší za 7 dní',
      html: membershipExpiry7DaysEmail(refCode)
    });
    results.push('✅ Expirace 7 dní odeslána');

    // 3) Expirace 3 dny
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to,
      subject: 'TEST: Členství vyprší za 3 dny',
      html: membershipExpiry3DaysEmail(refCode)
    });
    results.push('✅ Expirace 3 dny odeslána');

    // 3b) Expirace 0 dní (DNES)
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to,
      subject: 'TEST: Členství vyprší dnes',
      html: membershipExpiry0DaysEmail(refCode)
    });
    results.push('✅ Expirace 0 dní odeslána');

    // 4) Digest nepřečtených zpráv
    const digestHtmlInner = (typeof buildUnreadDigestEmail === 'function')
      ? buildUnreadDigestEmail('Testovací Pilot', sampleUnreadItems)
      : '<p>Digest HTML není dostupný.</p>';
    const digestHtml = wrapIfPossible(digestHtmlInner, 'Nepřečtené zprávy');
    const digestText = (typeof buildUnreadDigestText === 'function')
      ? buildUnreadDigestText('Testovací Pilot', sampleUnreadItems)
      : 'Digest TEXT není dostupný.';

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to,
      subject: 'TEST: Nepřečtené zprávy (digest)',
      html: digestHtml,
      text: digestText
    });
    results.push('✅ Digest nepřečtených zpráv odeslán');

    // 5) Digest nových poptávek
    const demandsHtmlInner = (typeof buildNewDemandsDigestEmailFancy === 'function')
      ? buildNewDemandsDigestEmailFancy('Testovací Pilot', sampleDemands)
      : '<p>Poptávky HTML není dostupný.</p>';
    const demandsHtml = wrapIfPossible(demandsHtmlInner, 'Nové poptávky');
    const demandsText = (typeof buildNewDemandsDigestText === 'function')
      ? buildNewDemandsDigestText('Testovací Pilot', sampleDemands)
      : 'Poptávky TEXT není dostupný.';

    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to,
      subject: 'TEST: Nové poptávky (posledních 24 h)',
      html: demandsHtml,
      text: demandsText
    });
    results.push('✅ Digest nových poptávek odeslán');

    res.send(`📨 Hotovo. Odesláno na ${to}:\n- ${results.join('\n- ')}`);
  } catch (err) {
    console.error('❌ /test-send-all-emails error:', err);
    res.status(500).send(`Chyba při odesílání: ${err.message}`);
  }
});


// === bezpečnost: omez na localhost/IP/heslo podle tvého middleware ===
// app.use('/send-outreach', allowLocalhostOnly); // příklad

app.post('/send-outreach', async (req, res) => {
  try{
    const { emails, template, subject, customNote } = req.body;
    if(!Array.isArray(emails) || !emails.length) return res.status(400).json({error:'No emails'});

    const buildHtml = (row) => {
      // použij stejné funkce jako v UI nebo svoje: generalOutreachMail / realEstateMail / logisticsMail
      const map = { general: generalOutreachMail, realty: realEstateMail, logistics: logisticsMail };
      const fn = map[template] || generalOutreachMail;
      // volitelné: doplň customNote do šablony (přidej parametr a vlož do wrapu)
      return fn(row?.name || null, customNote);
    };

    // po jednom (bezpečné vůči SMTP)
    for (const row of emails){
      const html = buildHtml(row);
      await transporter.sendMail({
        from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
        to: row.email,
        subject: subject || 'NajdiPilota.cz – dronní služby',
        html
      });
      await new Promise(r=>setTimeout(r, 1200)); // lehký limit, případně fronta
    }

    res.json({ ok:true, sent: emails.length });
  }catch(e){
    console.error('send-outreach error', e);
    res.status(500).json({ error:String(e?.message||e) });
  }
});

// Fallback – přímé odeslání jednoho e-mailu
app.post('/send-direct', async (req, res) => {
  try{
    const { to, subject, html } = req.body;
    if(!to || !html) return res.status(400).json({error:'missing to/html'});
    await transporter.sendMail({
      from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
      to, subject: subject || 'NajdiPilota.cz – dronní služby', html
    });
    res.json({ ok:true });
  }catch(e){
    console.error('send-direct error', e);
    res.status(500).json({ error:String(e?.message||e) });
  }
});



app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

