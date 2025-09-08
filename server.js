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

const app = express();


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




/*
app.get("/", (req, res) => {
  res.send("Vše běží!");
});
*/

const onboardingEmailContent = () => {
  return `
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
      <h2 style="color: #0077B6;">Vítejte na NajdiPilota.cz!</h2>
      <p style="font-size: 16px; color: #495057;">Děkujeme, že jste se zaregistrovali na <strong style="color: #0077B6;">NajdiPilota.cz</strong>! Jsme rádi, že se připojujete k naší komunitě profesionálních pilotů dronů.</p>
      <p style="font-size: 16px; color: #495057;"><strong>Zde je rychlý průvodce, jak začít:</strong></p>
      <ul style="font-size: 16px; color: #495057; padding-left: 20px;">
        <li><strong>Dokončete svůj profil:</strong> Ujistěte se, že máte všechny údaje aktuální. Pomůže to klientům snadněji vás najít.</li>
        <li><strong>Zůstaňte viditelní:</strong> Jakmile bude váš profil dokončen, můžete aktivovat viditelnost svého účtu a zajistit, aby vaše služby byly dostupné těm, kteří hledají kvalifikovaného pilota.</li>
        <li><strong>Využijte exkluzivní nabídky:</strong> Jako registrovaný pilot máte přístup k exkluzivním nabídkám a slevám od našich partnerů.</li>
      </ul>

      <p style="font-size: 16px; color: #495057;"><strong>Co to znamená pro vás?</strong></p>
      <p style="font-size: 16px; color: #495057;">Váš účet byl nastaven na typ <strong style="color: #258f01">Basic</strong>, což vám přináší následující výhody:</p>
      <ul style="font-size: 16px; color: #495057; padding-left: 20px;">
        <li><strong style="color: #258f01">Viditelnost a přehlednost:</strong> Vaše jméno a status dobrovolníka jsou viditelné pro inzerenty, kteří vás mohou snadněji najít.</li>
        <li><strong style="color: #258f01">2 Drony a 2 Specializace:</strong> Můžete mít až 2 drony a 2 specializace pro různé zakázky.</li>
        <li><strong style="color: #258f01">Aktuální dostupnost a ochota dojíždět:</strong> Vaše dostupnost je viditelná pro potenciální klienty.</li>
        <li><strong style="color: #258f01">Ověřený provozovatel:</strong> Pokud jste ověřený, vaše důvěryhodnost bude vyšší a přitahujete více klientů.</li>
        <li><strong style="color: #258f01">Napiš pilotovi:</strong> Inzerenti vás mohou kontaktovat přímo na platformě.</li>
        
      </ul>

      <p style="font-size: 16px; color: #495057;"><strong>Co kdybych měl Premium účet?</strong></p>
      <p style="font-size: 16px; color: #495057;">Pokud chcete plný přístup k funkcím a neomezené možnosti, <strong style="color: #8f06bd">Premium účet</strong> je pro vás ideální volbou:</p>
      <ul style="font-size: 16px; color: #495057; padding-left: 20px;">
        <li><strong style="color: #8f06bd;">Neomezený počet dronů:</strong> Už žádné limity, můžete mít tolik dronů, kolik budete potřebovat.</li>
        <li><strong style="color: #8f06bd;">Neomezený počet specializací:</strong> Můžete si přidat libovolný počet specializací.</li>
        <li><strong style="color: #8f06bd">Viditelné kontakty:</strong> E-mail a telefon jsou viditelné pro inzerenty, což znamená rychlý a přímý kontakt.</li>
        <li><strong style="color: #8f06bd">Výrazné fialové označení na mapě:</strong> Vaše profilová značka bude výrazně <span style= "color: #8f06bd">fialová</span>, což vás zviditelní mezi ostatními.</li>
       
        <li><strong style="color: #8f06bd">Přímá komunikace s inzerenty:</strong> Inzerent uvidí vaše kontaktní údaje a může vás oslovit napřímo.</li>
      </ul>

      <p style="font-size: 16px; color: #495057;"><strong>Co se stane, když mi vyprší členství?</strong></p>
      <p style="font-size: 16px; color: #495057;">Pokud vám členství vyprší, automaticky přejdete na typ účtu <strong style="color: #b0f759">Free</strong>, což znamená značná omezení:</p>
      <ul style="font-size: 16px; color: #495057; padding-left: 20px;">
        <li>Vidíte pouze omezené informace o ostatních pilotech (jméno, dobrovolník, 1 dron, 1 specializace).</li>
        <li>Nemáte přístup k kontaktům (email, telefon) ani k dalším dronům nebo specializacím.</li>
        
      </ul>

      <p style="font-size: 16px; color: #495057;">Pokud budete potřebovat prodloužit své členství, můžete to udělat v sekci, kde upravujete informace o pilotovi. Zde také najdete kód, který můžete poslat kamarádům. Když se zaregistrují, získáte 7 dní členství Basic zdarma, nebo prodloužíte své Premium o 7 dní, pokud jste už v tomto typu účtu.</p>

      <p style="font-size: 16px; color: #495057;"><strong>Co dál?</strong></p>
      <p style="font-size: 16px; color: #495057;">Teď je čas začít <strong>aktivně spravovat svůj profil</strong> a přitahovat více inzerentů! Pokud máte zájem o <strong style="color: #8f06bd;">upgradování na Premium účet</strong>, zvažte všechny skvělé výhody, které přináší.</p>

      <p style="font-size: 16px; color: #495057;">Pokud máte jakékoli dotazy nebo potřebujete pomoc, neváhejte se na nás obrátit na <a href="mailto:dronadmin@seznam.cz" style="color: #0077B6;">dronadmin@seznam.cz</a>.</p>

      <p style="font-size: 16px; color: #495057;">Těšíme se, že s námi budete růst a létat!</p>

      <p style="font-size: 16px; color: #495057;" class="footer">S pozdravem,<br />Tým NajdiPilota.cz</p>

      <p style="font-size: 16px; color: #495057;">Pro více informací navštivte naše <a href="https://www.najdipilota.cz/o-projektu.html" style="color: #0077B6;">O projektu</a> a <a href="https://www.najdipilota.cz/faq.html" style="color: #0077B6;">FAQ</a> stránky.</p>
    </div>
  `;
};

const membershipExpiry7DaysEmail = (refEmail) => {
  const refUrl = `https://najdipilota.cz/register.html?ref=${encodeURIComponent(refEmail)}`;
  return `
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
      <h2 style="color: #0077B6;">⏳ Vaše členství na NajdiPilota.cz brzy vyprší</h2>
      <p style="font-size: 16px; color: #495057;">
        Zbývá už jen <strong>7 dní</strong> do vypršení platnosti vašeho členství. 
        Aby váš profil zůstal viditelný pro klienty a inzerenty, doporučujeme ho včas prodloužit.
      </p>

      <p style="font-size: 16px; color: #495057;"><strong>Jak prodloužit členství?</strong></p>
      <ol style="font-size: 16px; color: #495057; padding-left: 20px;">
        <li>Přihlaste se na svůj účet pilota.</li>
        <li>V profilu pilota klikněte na tlačítko <strong style="color: #0077B6;">"Prodloužit členství"</strong>.</li>
      </ol>

      <p style="font-size: 16px; color: #495057;">
        Podrobné informace o typech účtů a možnostech prodloužení najdete zde:<br>
        <a href="https://www.najdipilota.cz/subscription.html" style="color: #0077B6;">Možnosti předplatného</a>
      </p>

      <hr style="margin: 20px 0;">

      <h3 style="color: #258f01;">🎁 Získejte 7 dní navíc zdarma!</h3>
      <p style="font-size: 16px; color: #495057;">
        Pozvěte svého kamaráda k registraci a získejte <strong>+7 dní členství zdarma</strong>.  
        Stačí mu poslat tento odkaz:
      </p>
      <div style="background: #f1f1f1; padding: 10px; font-size: 16px; text-align: center; border-radius: 6px; word-break: break-all;">
        ${refUrl}
      </div>

      <p style="font-size: 14px; color: #6c757d; margin-top: 10px;">
        Jakmile se váš kamarád zaregistruje přes tento odkaz, automaticky se vám přičte 7 dní k aktuálnímu členství.
      </p>

      <p style="font-size: 16px; color: #495057;">S pozdravem,<br>Tým NajdiPilota.cz</p>
    </div>
  `;
};

const membershipExpiry3DaysEmail = (refEmail) => {
  const refUrl = `https://najdipilota.cz/register.html?ref=${encodeURIComponent(refEmail)}`;
  return `
    <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
      <h2 style="color: red;">⚠️ Poslední 3 dny pro prodloužení členství!</h2>
      <p style="font-size: 16px; color: #495057;">
        Vaše členství na <strong>NajdiPilota.cz</strong> vyprší už za <strong>3 dny</strong>. 
        Po tomto datu bude váš účet automaticky převeden na typ <strong style="color: #b0f759;">Free</strong> s omezenými funkcemi.
      </p>

      <p style="font-size: 16px; color: #495057;"><strong>Prodloužení je snadné:</strong></p>
      <ol style="font-size: 16px; color: #495057; padding-left: 20px;">
        <li>Přihlaste se na svůj účet pilota.</li>
        <li>Klikněte v profilu pilota na <strong style="color: #0077B6;">"Prodloužit členství"</strong>.</li>
      </ol>

      <p style="font-size: 16px; color: #495057;">
        Všechny varianty a ceny najdete zde:<br>
        <a href="https://www.najdipilota.cz/subscription.html" style="color: #0077B6;">Možnosti předplatného</a>
      </p>

      <hr style="margin: 20px 0;">

      <h3 style="color: #258f01;">🎁 Prodlužte zdarma o 7 dní!</h3>
      <p style="font-size: 16px; color: #495057;">
        Nezapomeňte – můžete získat <strong>+7 dní členství zdarma</strong>, když pozvete kamaráda.  
        Pošlete mu tento odkaz:
      </p>
      <div style="background: #f1f1f1; padding: 10px; font-size: 16px; text-align: center; border-radius: 6px; word-break: break-all;">
        ${refUrl}
      </div>

      <p style="font-size: 14px; color: #6c757d; margin-top: 10px;">
        Jakmile se zaregistruje přes tento odkaz, ihned se vám přičte 7 dní k vašemu členství.
      </p>

      <p style="font-size: 16px; color: #495057;">S pozdravem,<br>Tým NajdiPilota.cz</p>
    </div>
  `;
};



// Registrace
app.post('/register', async (req, res) => {
  const {
    name, email, password, phone,
    street, city, zip, region, ref
  } = req.body;
  console.log("🔍 Request body:", req.body);

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
        email,
        password_hash,
        phone,
        street,
        city,
        zip,
        region,
        lat,
        lon,
        visible_valid,
        ref || null,
        "Basic",
        "ANO"
      ]
    );

  // Pokud referrer existuje, přidáme bonus
if (ref) {
  try {
    const refResult = await pool.query(
      `WITH updated_account AS (
         UPDATE pilots
         SET 
           type_account = 
             CASE 
               WHEN type_account IS NULL OR type_account = 'Free' THEN 'Basic'  -- Pokud je účet Free, změň ho na Basic
               ELSE type_account
             END,
           visible_valid = 
             CASE 
               WHEN visible_valid IS NULL THEN CURRENT_DATE + INTERVAL '7 days'
               WHEN type_account = 'Premium' THEN visible_valid + INTERVAL '7 days' -- Prodloužení pro Premium účet
               ELSE visible_valid + INTERVAL '7 days'
             END
         WHERE email = $1
         RETURNING email, type_account
       )
       SELECT * FROM updated_account`,
      [ref]
    );

    if (refResult.rowCount > 0) {
      const accountType = refResult.rows[0].type_account;
      if (accountType === 'Premium') {
        console.log(`🎉 Připsáno 7 dní na Premium účet pilotovi, který pozval: ${ref}`);
      } else {
        console.log(`🎉 Připsáno 7 dní na Basic účet pilotovi, který pozval: ${ref}`);
      }
    }
  } catch (err) {
    console.warn("⚠️ Nepodařilo se připsat bonus referrerovi:", err);
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
  
await transporter.sendMail({
   from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
   to: email,
   subject: "Vítejte na NajdiPilota.cz!",
   html: onboardingEmailContent()  // Odeslání onboardingového e-mailu
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

    res.send("Přihlášení úspěšné");

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
    pass: 'letamsdrony12'
  }
});

app.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send("E-mail je povinný.");

  try {
    const result = await pool.query(`SELECT * FROM pilots WHERE email = $1`, [email]);
    const user = result.rows[0];
    if (!user) return res.status(404).send("Uživatel s tímto e-mailem nebyl nalezen.");

    const newPassword = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(newPassword, 10);

    await pool.query(`UPDATE pilots SET password_hash = $1 WHERE email = $2`, [hash, email]);

    await transporter.sendMail({
      from: '"Dronová mapa" <dronadmin@seznam.cz>',
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

  // natáhni stará data (kvůli omezením a defaultům)
  const oldDataResult = await pool.query(
    "SELECT visible, visible_valid, visible_payment, type_account, available AS old_available FROM pilots WHERE email = $1",
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

  // Geokódování
  const location = [street, city, zip, region].filter(Boolean).join(", ");
  let lat = null, lon = null;
  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(location)}&limit=1`,
      { headers: { "User-Agent": "DronMapApp/1.0" } }
    );
    const data = await response.json();
    if (Array.isArray(data) && data.length > 0) {
      lat = parseFloat(data[0].lat);
      lon = parseFloat(data[0].lon);
    } else {
      console.warn("❗Adresa se nepodařilo geokódovat:", location);
    }
  } catch (err) {
    console.error("Chyba při geokódování:", err);
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

console.log("Záznam uložen do databáze.");


    res.status(201).send("Registrace úspěšná!");
  } catch (err) {
    console.error("Chyba při registraci:", err);
    res.status(500).send("Nastala chyba při registraci.");
  }
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
      'SELECT id FROM conversations WHERE pilot_id = $1 AND advertiser_id = $2 LIMIT 1',
      [pilotId, advertiserId]
    );

    let conversationId;

    if (existingConversation.rowCount > 0) {
      // If the conversation exists, use the existing conversationId
      conversationId = existingConversation.rows[0].id;
    } else {
      // If no conversation exists, create a new one
      const conversationResult = await pool.query(
        `INSERT INTO conversations (pilot_id, advertiser_id) 
         VALUES ($1, $2) 
         RETURNING id`,
        [pilotId, advertiserId]
      );
      conversationId = conversationResult.rows[0].id;
    }

    res.json({ success: true, conversationId });

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
         m.id, m.sender_id, m.message, m.created_at,
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





app.post('/send-message', async (req, res) => {
  const { conversationId, senderEmail, message } = req.body;

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

    // 2) Urči roli odesílatele podle e-mailu a ověř, že patří do této konverzace
    const pilotRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [senderEmail]);
    const advRes   = await pool.query('SELECT id FROM advertisers WHERE email = $1', [senderEmail]);

    let senderId = null;
    if (pilotRes.rowCount > 0 && pilotRes.rows[0].id === pilot_id) {
      senderId = pilot_id; // posílá pilot
    } else if (advRes.rowCount > 0 && advRes.rows[0].id === advertiser_id) {
      senderId = advertiser_id; // posílá inzerent
    } else {
      return res.status(403).json({ success: false, message: 'Odesílatel do konverzace nepatří' });
    }

    // 3) Ulož zprávu
    const inserted = await pool.query(
      `INSERT INTO messages (conversation_id, sender_id, message)
       VALUES ($1, $2, $3)
       RETURNING id, sender_id, message, created_at`,
      [conversationId, senderId, message]
    );

    // 4) Vrať rovnou i sender_email a sender_role (frontend to hned obarví správně)
    const enriched = await pool.query(
      `SELECT 
         m.id, m.sender_id, m.message, m.created_at,
         CASE WHEN m.sender_id = c.pilot_id THEN p.email ELSE a.email END AS sender_email,
         CASE WHEN m.sender_id = c.pilot_id THEN 'pilot' ELSE 'advertiser' END AS sender_role
       FROM messages m
       JOIN conversations c ON c.id = m.conversation_id
       JOIN pilots p ON p.id = c.pilot_id
       JOIN advertisers a ON a.id = c.advertiser_id
       WHERE m.id = $1`,
      [inserted.rows[0].id]
    );

    return res.json({ success: true, newMessage: enriched.rows[0] });

  } catch (err) {
    console.error("Chyba při odesílání zprávy:", err);
    res.status(500).json({ success: false, message: 'Chyba při odesílání zprávy' });
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
      'SELECT id FROM conversations WHERE pilot_id = $1 AND advertiser_id = $2 LIMIT 1',
      [pilotId, advertiserId]
    );

    let conversationId;

    if (existingConversation.rowCount > 0) {
      // If the conversation exists, use the existing conversationId
      conversationId = existingConversation.rows[0].id;
    } else {
      // If no conversation exists, create a new one
      const conversationResult = await pool.query(
        `INSERT INTO conversations (pilot_id, advertiser_id) 
         VALUES ($1, $2) 
         RETURNING id`,
        [pilotId, advertiserId]
      );
      conversationId = conversationResult.rows[0].id;
    }

    res.json({ success: true, conversationId });

  } catch (err) {
    console.error("Chyba při vytváření konverzace:", err);
    res.status(500).json({ success: false, message: 'Chyba serveru při vytváření konverzace' });
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


// Get all conversations for a pilot
app.get('/get-pilot-conversations', async (req, res) => {
  const { pilotEmail } = req.query;

  try {
    // First get pilot ID
    const pilotResult = await pool.query(
      'SELECT id FROM pilots WHERE email = $1',
      [pilotEmail]
    );

    if (pilotResult.rowCount === 0) {
      return res.json({ success: false, message: 'Pilot not found' });
    }

    const pilotId = pilotResult.rows[0].id;

    // Get all conversations with advertisers
    const conversations = await pool.query(`
      SELECT 
        c.id,
        a.email AS advertiser_email,
        a.name AS advertiser_name,
        (SELECT message FROM messages 
         WHERE conversation_id = c.id 
         ORDER BY created_at DESC LIMIT 1) AS last_message,
        (SELECT created_at FROM messages 
         WHERE conversation_id = c.id 
         ORDER BY created_at DESC LIMIT 1) AS last_message_time,
        EXISTS (
          SELECT 1 FROM messages 
          WHERE conversation_id = c.id 
          AND sender_id != $1 
          AND (created_at > (
            SELECT last_seen FROM conversation_views 
            WHERE conversation_id = c.id AND user_id = $1
            LIMIT 1
          ) OR NOT EXISTS (
            SELECT 1 FROM conversation_views 
            WHERE conversation_id = c.id AND user_id = $1
          ))
        ) AS unread
      FROM conversations c
      JOIN advertisers a ON c.advertiser_id = a.id
      WHERE c.pilot_id = $1
      ORDER BY last_message_time DESC NULLS LAST
    `, [pilotId]);

    res.json({
      success: true,
      conversations: conversations.rows
    });
  } catch (err) {
    console.error("Error fetching pilot conversations:", err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Mark conversation as read
app.post('/mark-conversation-read', async (req, res) => {
  const { conversationId, userId } = req.body;
  
  try {
    await pool.query(`
      INSERT INTO conversation_views (conversation_id, user_id, last_seen)
      VALUES ($1, $2, NOW())
      ON CONFLICT (conversation_id, user_id) 
      DO UPDATE SET last_seen = NOW()
    `, [conversationId, userId]);
    
    res.json({ success: true });
  } catch (err) {
    console.error("Error marking conversation as read:", err);
    res.status(500).json({ success: false });
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
        `SELECT id, title, description, location, region, budget, deadline, advertiser_email, created_at
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
      `SELECT id, title, description, location, region, budget, deadline, advertiser_email, created_at
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

// POST /poptavky – vložení poptávky inzerentem
app.post('/poptavky', async (req, res) => {
  try {
     const { title, description, location, region, budget, deadline, public: isPublic } = req.body;
    const advertiser_email = (req.session?.email || '').toLowerCase();
    if (!advertiser_email) return res.status(401).send('Nepřihlášený inzerent.');
    if (!title || !location) return res.status(400).send('Chybí povinná pole (název a lokalita).');

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
        Number.isFinite(+budget) ? +budget : null,
        deadline || null,
        isPublic !== false, // default true
        advertiser_email
      ]
    );

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
          subject: "Vaše členství vyprší za 7 dní",
          html: membershipExpiry7DaysEmail(pilot.email)
        });
      }

      if (daysLeft === 3) {
        await transporter.sendMail({
          from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
          to: pilot.email,
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
        // Zkontroluj, zda je připojen emailový server
        await transporter.verify(); // Tato funkce ověřuje připojení k serveru
        console.log('Email server connection is ready');

        // Definování proměnné pro piloty (získání pilotů z DB)
        let query = `
            SELECT p.id, p.email, p.name, p.type_account
            FROM pilots p
            LEFT JOIN consents c ON p.id = c.user_id AND c.consent_type = 'public_contact'
            WHERE p.type_account IN ('Premium', 'Basic') -- Vybírá všechny piloty s těmito typy účtů
        `;
        
        let queryParams = [];

        // Pokud je posláno pole 'ids', přidáme podmínku pro konkrétní piloty
        if (req.body.ids && req.body.ids.length > 0) {
            query += ` AND p.id IN (${req.body.ids.map((_, i) => `$${i + 1}`).join(',')})`;
            queryParams = [...req.body.ids];
        }

        // Spustí dotaz na získání všech pilotů
        const result = await pool.query({
            text: query,
            values: queryParams,
            timeout: 10000 // 10 sekundy timeout
        });

        const pilotsWithoutConsent = result.rows;  // Seznam všech pilotů, včetně těch, kteří již mají GDPR souhlas

        if (pilotsWithoutConsent.length === 0) {
            return res.send("Žádní piloti nevyžadují připomenutí GDPR souhlasu.");
        }

        let successCount = 0;
        let failedEmails = [];

        // Posílání GDPR připomínek pilotům
        for (const pilot of pilotsWithoutConsent) {
    try {
        const emailContent = {
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: pilot.email,
            subject: "Důležitá informace k vašemu účtu na NajdiPilota.cz – Potřebujeme váš souhlas s GDPR",
            html: `
                <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #0077B6;">Důležitá informace k vašemu účtu na NajdiPilota.cz</h2>
                    <p style="font-size: 16px; color: #495057;">Dobrý den, <strong>${pilot.name}</strong>,</p>
                    <p style="font-size: 16px; color: #495057;">
                        Děkujeme, že jste součástí komunity <strong style="color: #0077B6;">NajdiPilota.cz</strong>.
                    </p>
                    <p style="font-size: 16px; color: #495057;">
                        Váš účet je <strong style="color: #258f01">${pilot.type_account}</strong>, ale chybí nám váš souhlas se zobrazením kontaktů.
                    </p>
                    <p style="font-size: 16px; color: #495057;">
                        Pokud chcete udělit souhlas s GDPR, klikněte na tento odkaz:
                    </p>
                    <p style="font-size: 16px; color: #495057;">
                        <a href="https://www.najdipilota.cz/index.html" style="font-size: 18px; color: #0077B6; text-decoration: none;">Klikněte zde pro přihlášení a udělení souhlasu s GDPR</a>
                    </p>
                    <p style="font-size: 16px; color: #495057;">
                        Po přihlášení na stránce budete mít možnost souhlas s GDPR udělit.
                    </p>
                    <p style="font-size: 16px; color: #495057;">
                        Pokud máte jakékoliv dotazy nebo potřebujete další informace, neváhejte nás kontaktovat na <a href="mailto:dronadmin@seznam.cz" style="color: #0077B6;">dronadmin@seznam.cz</a>.
                    </p>
                    <p style="font-size: 16px; color: #495057;">
                        Děkujeme vám za spolupráci a těšíme se na další spolupráci!
                    </p>

                    <p style="font-size: 16px; color: #495057;">
                        S pozdravem,<br />Tým NajdiPilota.cz
                    </p>

                    <p style="font-size: 14px; color: #6c757d;">
                        Tento e-mail je automaticky generován na základě vašeho účtu na NajdiPilota.cz. Pokud nemáte zájem o tuto připomínku, ignorujte prosím tento e-mail.
                    </p>
                    <p style="font-size: 14px; color: #6c757d;">
                        <a href="https://www.najdipilota.cz/o-projektu.html" style="color: #0077B6;">O projektu</a> | <a href="https://www.najdipilota.cz/faq.html" style="color: #0077B6;">FAQ</a>
                    </p>
                </div>
            `,
            text: `
                Dobrý den ${pilot.name},

                Děkujeme, že jste součástí komunity NajdiPilota.cz.

                Váš účet je ${pilot.type_account}, ale chybí nám váš souhlas se zobrazením kontaktů.

                Pokud chcete udělit souhlas s GDPR, přihlaste se na následujícím odkazu:
                https://www.najdipilota.cz/index.html

                Po přihlášení budete mít možnost souhlas s GDPR udělit.

                Pokud máte jakékoliv dotazy nebo potřebujete další informace, kontaktujte nás na: dronadmin@seznam.cz

                S pozdravem,
                Tým NajdiPilota.cz

                Tento e-mail je automaticky generován na základě vašeho účtu na NajdiPilota.cz. Pokud nemáte zájem o tuto připomínku, ignorujte prosím tento e-mail.

                Pro více informací navštivte:
                - O projektu: https://www.najdipilota.cz/o-projektu.html
                - FAQ: https://www.najdipilota.cz/faq.html
            `
        };

        await transporter.sendMail(emailContent);  // Odeslání emailu
        successCount++;
        console.log(`✅ GDPR reminder sent to: ${pilot.email}`);

        await new Promise(resolve => setTimeout(resolve, 500));  // Malé zpoždění mezi e-maily
    } catch (err) {
        console.error(`❌ Error sending to ${pilot.email}:`, err.message);
        failedEmails.push(pilot.email);
    }
}

        // Vytvoření odpovědi
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
app.listen(PORT, () => {
  console.log(`Server běží na portu ${PORT}`);
});

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
        if (daysLeft === 7) {
          await transporter.sendMail({
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: pilot.email,
            subject: 'Vaše členství vyprší za 7 dní',
            html: membershipExpiry7DaysEmail(pilot.email)
          });
        } else if (daysLeft === 3) {
          await transporter.sendMail({
            from: '"NajdiPilota.cz" <dronadmin@seznam.cz>',
            to: pilot.email,
            subject: 'Vaše členství vyprší za 3 dny',
            html: membershipExpiry3DaysEmail(pilot.email)
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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

