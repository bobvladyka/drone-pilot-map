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

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
    sslmode: 'require'
  }
});

app.use(prerender);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session konfigurace
app.use(session({
    secret: process.env.SESSION_SECRET || 'super_tajne_heslo',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: true } // true pokud jedeš na HTTPS
}));

app.use(cors({
  origin: 'https://www.najdipilota.cz', // Povolit pouze vaši doménu
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Povolené HTTP metody
  credentials: true // Povolit cookies a autentizační hlavičky
}));

// Admin route protection middleware
function requireAdminLogin(req, res, next) {
    if (req.session && req.session.isAdmin) {
        return next();
    }
    return res.redirect('/adminland.html');
}

app.use(express.static(path.join(__dirname, 'public')));






// ADMIN LOGIN
app.post('/admin-login', (req, res) => {
    const { username, password } = req.body;
    const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'strongpassword123';

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        return res.json({ success: true });
    }
    return res.status(401).json({ success: false, message: 'Neplatné přihlašovací údaje' });
});

// ADMIN LOGOUT
app.get('/admin-logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/adminland.html');
    });
});

// ADMIN HTML – chráněné
app.get('/admin.html', requireAdminLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});


app.get("/", (req, res) => {
  res.send("Vše běží!");
});


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



// Registrace
app.post('/register', async (req, res) => {
  const {
    name, email, password, phone,
    street, city, zip, region, ref
  } = req.body;
  console.log("🔍 Request body:", req.body);

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
visible_valid.setDate(visible_valid.getDate() + 7);
console.log("Datum po přidání 7 dní: ", visible_valid);


  const insertPilot = await pool.query(
    `INSERT INTO pilots (
      name, email, password_hash, phone, street, city, zip, region,
      latitude, longitude, visible_valid, ref_by_email, type_account
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    RETURNING id`,
    [name, email, password_hash, phone, street, city, zip, region,
     lat, lon, visible_valid, ref || null, "Basic"]  // Nastavení typu účtu na "Basic"
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
        latitude, longitude, 
        password_hash, website,
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
  specialization,
  volunteer,
  registrationnumber,
  available,
  visible,
  visible_payment,
  visible_valid
} = req.body;

if (visible === undefined || visible === null) {
  const oldDataResult = await pool.query(
    "SELECT visible, visible_valid, visible_payment, type_account FROM pilots WHERE email = $1",
    [email]
  );
  const oldPilotData = oldDataResult.rows[0];

    if (!oldPilotData) {
      return res.status(404).send("Pilot nenalezen.");
    }

    // Pokud nebyly poslány hodnoty viditelnosti, použij staré
    if (visible === undefined || visible === null) visible = oldPilotData.visible;
    if (!visible_valid) visible_valid = oldPilotData.visible_valid;
    if (!visible_payment) visible_payment = oldPilotData.visible_payment;

    // 🔒 Restrikce pro Free účty
    if (oldPilotData.type_account === "Free") {
  available = "ANO"; // vždy ANO
  website = null;    // zakázat web
  note = null;       // zakázat poznámku
  registrationnumber = null; // 🚫 zakázat registrační číslo
  visible = "ANO"; 

  if (specialization) {
    specialization = specialization.split(",")[0]; // jen první specializace
  }

  if (drones) {
    drones = drones.split(",")[0]; // 🚫 jen první dron
  }
}
// 🔒 Omezení pro Basic účet
if (oldPilotData.type_account === "Basic") {

   if (!available) {
    available = oldPilotData.available;
  }

  // Povolené: available, registrationnumber, phone, email, website(portfolio)
  // Omezení: max 3 specializace, max 2 drony
  if (specialization) {
    specialization = specialization.split(",").slice(0, 3).join(","); // max 3
  }
  if (drones) {
    drones = drones.split(",").slice(0, 2).join(","); // max 2
  }
}

// 🛡️ Zajištění, že available má vždy ANO nebo NE
if (available !== "ANO" && available !== "NE") {
  available = "NE";
}


    // Převod visible na ANO/NE
    visible = "ANO";

if (!visible) visible = oldData.visible;
if (!visible_valid) visible_valid = oldData.visible_valid;
if (!visible_payment) visible_payment = oldData.visible_payment;
} else {
  visible = visible ? "ANO" : "NE";
}  const location = [street, city, zip, region].filter(Boolean).join(', ');

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
    console.warn("❗Adresa se nepodařilo geokódovat:", location);
  }
} catch (err) {
  console.error("Chyba při geokódování:", err);
}

  try {
    // DEBUG: Logování hodnot před odesláním do DB
    console.log("Hodnoty pro update:", {
      name, phone, website, street, city, zip, region,
      drones, note, travel, licenses, specialization,
      volunteer, lat, lon, registrationnumber, 
      available // Toto by mělo být 'ANO' nebo 'NE'
    });

    const result = await pool.query(
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
    specialization = $12, 
    volunteer = $13, 
    latitude = $14, 
    longitude = $15,
    registrationnumber = $16,
    available = $17,
    visible = $18,
    visible_payment = $19,
    visible_valid = $20
  WHERE email = $21
  RETURNING *`,
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
    specialization || null,
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

  

    res.send("✅ Údaje byly úspěšně aktualizovány.");
  } catch (err) {
    console.error("❌ ÚPLNÁ CHYBOVÁ ZPRÁVA:", err);
    console.error("❌ STACK TRACE:", err.stack); // Detaily o místě chyby
    res.status(500).json({
      error: "Chyba při aktualizaci",
      details: err.message, // Posíláme klientovi konkrétní chybovou zprávu
      stack: process.env.NODE_ENV === "development" ? err.stack : undefined
    });
  }

});


app.post('/delete-all', requireAdminLogin, async (req, res) => {
  try {
    await pool.query('DELETE FROM pilots');
    res.send("✅ Všechny záznamy byly smazány.");
  } catch (err) {
    console.error("❌ Chyba při mazání:", err);
    res.status(500).send("Chyba při mazání.");
  }
});

app.post('/delete-selected',  requireAdminLogin, async (req, res) => {
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

// Admin login endpoint
app.post('/admin-login', async (req, res) => {
    const { username, password } = req.body;

    const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
    const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'strongpassword123';

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        return res.json({ success: true });
    }
    return res.status(401).json({ success: false, message: 'Neplatné přihlašovací údaje' });
});




app.get('/admin.html', requireAdminLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin-logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/adminland.html');
    });
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

    // Pokud uplynul měsíc, přepneme účet na Free
    if (user.visible_valid && new Date(user.visible_valid) <= currentDate) {
      await pool.query(
        `UPDATE pilots SET type_account = $1 WHERE id = $2`,
        ["Free", userId]
      );
      console.log(`Pilot ${user.email} byl přepnut na typ účtu Free.`);
      user.type_account = "Free";  // Aktualizujeme typ účtu v odpovědi
    }

    res.json(user);
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


// Získání seznamu konverzací pro uživatele
app.get('/chat-conversations', async (req, res) => {
  const { userEmail, userType } = req.query; // 'pilot' nebo 'inzerent'
  
  try {
    let query;
    if (userType === 'pilot') {
      query = `
        SELECT c.id, a.email as partner_email, MAX(m.created_at) as last_message_time
        FROM conversations c
        JOIN advertisers a ON c.advertiser_id = a.id
        JOIN pilots p ON c.pilot_id = p.id
        LEFT JOIN messages m ON m.conversation_id = c.id
        WHERE p.email = $1
        GROUP BY c.id, a.email
        ORDER BY last_message_time DESC NULLS LAST`;
    } else {
      query = `
        SELECT c.id, p.email as partner_email, MAX(m.created_at) as last_message_time
        FROM conversations c
        JOIN pilots p ON c.pilot_id = p.id
        JOIN advertisers a ON c.advertiser_id = a.id
        LEFT JOIN messages m ON m.conversation_id = c.id
        WHERE a.email = $1
        GROUP BY c.id, p.email
        ORDER BY last_message_time DESC NULLS LAST`;
    }

    const result = await pool.query(query, [userEmail]);
    res.json(result.rows);
  } catch (err) {
    console.error("Chyba při načítání konverzací:", err);
    res.status(500).send("Chyba serveru");
  }
});


// Získání ID uživatele (pilot/inzerent)
app.get('/get-user-id', async (req, res) => {
  const { email, type } = req.query;
  
  try {
    let result;
    if (type === 'pilot') {
      result = await pool.query('SELECT id FROM pilots WHERE email = $1', [email]);
    } else {
      result = await pool.query('SELECT id FROM advertisers WHERE email = $1', [email]);
    }
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Uživatel nenalezen' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Chyba při hledání uživatele:', err);
    res.status(500).send('Chyba serveru');
  }
});

// Najít nebo vytvořit konverzaci
app.post('/find-or-create-conversation', async (req, res) => {
  const { pilotId, advertiserId } = req.body;
  
  try {
    // Nejprve zkusíme najít existující konverzaci
    const findResult = await pool.query(
      `SELECT * FROM conversations 
       WHERE pilot_id = $1 AND advertiser_id = $2`,
      [pilotId, advertiserId]
    );
    
    if (findResult.rowCount > 0) {
      return res.json(findResult.rows[0]);
    }
    
    // Pokud neexistuje, vytvoříme novou
    const createResult = await pool.query(
      `INSERT INTO conversations (pilot_id, advertiser_id)
       VALUES ($1, $2) RETURNING *`,
      [pilotId, advertiserId]
    );
    
    res.json(createResult.rows[0]);
  } catch (err) {
    console.error('Chyba při vytváření konverzace:', err);
    res.status(500).send('Chyba serveru');
  }
});

// Získání konverzace s detailem partnera
app.get('/get-conversation', async (req, res) => {
  const { id, currentUserType } = req.query;
  
  try {
    const result = await pool.query(
      `SELECT c.*, 
              p.email as pilot_email, p.name as pilot_name,
              a.email as advertiser_email, a.name as advertiser_name
       FROM conversations c
       JOIN pilots p ON c.pilot_id = p.id
       JOIN advertisers a ON c.advertiser_id = a.id
       WHERE c.id = $1`,
      [id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Konverzace nenalezena' });
    }
    
    const conversation = result.rows[0];
    
    // Určíme, kdo je partner
    const partner = currentUserType === 'pilot' ? {
      email: conversation.advertiser_email,
      name: conversation.advertiser_name,
      type: 'inzerent'
    } : {
      email: conversation.pilot_email,
      name: conversation.pilot_name,
      type: 'pilot'
    };
    
    res.json({
      id: conversation.id,
      partner
    });
  } catch (err) {
    console.error('Chyba při načítání konverzace:', err);
    res.status(500).send('Chyba serveru');
  }
});

// Získání zpráv v konverzaci
app.get('/get-messages', async (req, res) => {
  const { conversationId } = req.query;
  
  try {
    const result = await pool.query(
      `SELECT m.*, 
              CASE 
                WHEN m.sender_id = p.id THEN 'pilot' 
                ELSE 'inzerent' 
              END as sender_type
       FROM messages m
       JOIN conversations c ON m.conversation_id = c.id
       JOIN pilots p ON c.pilot_id = p.id
       WHERE m.conversation_id = $1
       ORDER BY m.created_at ASC`,
      [conversationId]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error('Chyba při načítání zpráv:', err);
    res.status(500).send('Chyba serveru');
  }
});

// Získání konverzací pro uživatele
app.get('/api/conversations', async (req, res) => {
  const { userEmail, userType } = req.query;
  
  try {
    let query;
    if (userType === 'pilot') {
      query = `
        SELECT c.id, a.email as partner_email, a.name as partner_name, 
               m.message, m.created_at
        FROM conversations c
        JOIN advertisers a ON c.advertiser_id = a.id
        LEFT JOIN (
          SELECT conversation_id, message, created_at,
                 ROW_NUMBER() OVER (PARTITION BY conversation_id ORDER BY created_at DESC) as rn
          FROM messages
        ) m ON m.conversation_id = c.id AND m.rn = 1
        WHERE c.pilot_id = (SELECT id FROM pilots WHERE email = $1)`;
    } else {
      query = `
        SELECT c.id, p.email as partner_email, p.name as partner_name, 
               m.message, m.created_at
        FROM conversations c
        JOIN pilots p ON c.pilot_id = p.id
        LEFT JOIN (
          SELECT conversation_id, message, created_at,
                 ROW_NUMBER() OVER (PARTITION BY conversation_id ORDER BY created_at DESC) as rn
          FROM messages
        ) m ON m.conversation_id = c.id AND m.rn = 1
        WHERE c.advertiser_id = (SELECT id FROM advertisers WHERE email = $1)`;
    }
    
    const result = await pool.query(query, [userEmail]);
    
    const conversations = result.rows.map(row => ({
      id: row.id,
      partnerEmail: row.partner_email,
      partnerName: row.partner_name,
      lastMessage: row.message ? {
        message: row.message,
        created_at: row.created_at
      } : null
    }));
    
    res.json(conversations);
  } catch (err) {
    console.error('Chyba při načítání konverzací:', err);
    res.status(500).json([]);
  }
});

// Vytvoření nové konverzace
app.post('/api/conversations', async (req, res) => {
  const { userEmail, userType, partnerEmail } = req.body;
  
  try {
    // Najdeme ID účastníků
    let pilotId, advertiserId;
    
    if (userType === 'pilot') {
      // Uživatel je pilot, partner je inzerent
      const pilotRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [userEmail]);
      const advertiserRes = await pool.query('SELECT id FROM advertisers WHERE email = $1', [partnerEmail]);
      
      if (pilotRes.rowCount === 0 || advertiserRes.rowCount === 0) {
        return res.status(404).json({ error: 'Uživatel nenalezen' });
      }
      
      pilotId = pilotRes.rows[0].id;
      advertiserId = advertiserRes.rows[0].id;
    } else {
      // Uživatel je inzerent, partner je pilot
      const advertiserRes = await pool.query('SELECT id FROM advertisers WHERE email = $1', [userEmail]);
      const pilotRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [partnerEmail]);
      
      if (pilotRes.rowCount === 0 || advertiserRes.rowCount === 0) {
        return res.status(404).json({ error: 'Uživatel nenalezen' });
      }
      
      pilotId = pilotRes.rows[0].id;
      advertiserId = advertiserRes.rows[0].id;
    }
    
    // Zkontrolujeme, zda konverzace již existuje
    const existingRes = await pool.query(
      'SELECT id FROM conversations WHERE pilot_id = $1 AND advertiser_id = $2',
      [pilotId, advertiserId]
    );
    
    if (existingRes.rowCount > 0) {
      return res.status(400).json({ error: 'Konverzace již existuje' });
    }
    
    // Vytvoříme novou konverzaci
    const insertRes = await pool.query(
      'INSERT INTO conversations (pilot_id, advertiser_id) VALUES ($1, $2) RETURNING *',
      [pilotId, advertiserId]
    );
    
    res.json(insertRes.rows[0]);
  } catch (err) {
    console.error('Chyba při vytváření konverzace:', err);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Získání zpráv v konverzaci
app.get('/api/messages', async (req, res) => {
  const { conversationId } = req.query;
  
  try {
    const result = await pool.query(
      `SELECT m.*, 
              CASE 
                WHEN m.sender_id = p.id THEN p.email
                ELSE a.email
              END as sender_email
       FROM messages m
       JOIN conversations c ON m.conversation_id = c.id
       JOIN pilots p ON c.pilot_id = p.id
       JOIN advertisers a ON c.advertiser_id = a.id
       WHERE m.conversation_id = $1
       ORDER BY m.created_at ASC`,
      [conversationId]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error('Chyba při načítání zpráv:', err);
    res.status(500).json([]);
  }
});

// Odeslání zprávy
app.post('/api/messages', async (req, res) => {
  const { conversation_id, sender_email, message } = req.body;
  
  try {
    // Najdeme ID odesílatele
    let senderId;
    const pilotRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [sender_email]);
    if (pilotRes.rowCount > 0) {
      senderId = pilotRes.rows[0].id;
    } else {
      const advertiserRes = await pool.query('SELECT id FROM advertisers WHERE email = $1', [sender_email]);
      if (advertiserRes.rowCount > 0) {
        senderId = advertiserRes.rows[0].id;
      } else {
        return res.status(404).json({ error: 'Uživatel nenalezen' });
      }
    }
    
    // Uložíme zprávu
    const result = await pool.query(
      `INSERT INTO messages (conversation_id, sender_id, message)
       VALUES ($1, $2, $3) RETURNING *`,
      [conversation_id, senderId, message]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Chyba při odesílání zprávy:', err);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Najde nebo vytvoří konverzaci
app.post('/api/find-or-create-conversation', async (req, res) => {
  const { pilotEmail, inzerentEmail } = req.body;

  try {
    // 1. Najdeme ID účastníků
    const pilotRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [pilotEmail]);
    const inzerentRes = await pool.query('SELECT id FROM advertisers WHERE email = $1', [inzerentEmail]);
    
    if (pilotRes.rowCount === 0 || inzerentRes.rowCount === 0) {
      return res.status(404).json({ error: 'Pilot nebo inzerent nenalezen' });
    }
    
    const pilotId = pilotRes.rows[0].id;
    const inzerentId = inzerentRes.rows[0].id;
    
    // 2. Zkusíme najít existující konverzaci
    const existingRes = await pool.query(
      'SELECT id FROM conversations WHERE pilot_id = $1 AND advertiser_id = $2',
      [pilotId, inzerentId]
    );
    
    if (existingRes.rowCount > 0) {
      return res.json({ id: existingRes.rows[0].id });
    }
    
    // 3. Pokud neexistuje, vytvoříme novou
    const newRes = await pool.query(
      'INSERT INTO conversations (pilot_id, advertiser_id) VALUES ($1, $2) RETURNING id',
      [pilotId, inzerentId]
    );
    
    res.json({ id: newRes.rows[0].id });
  } catch (err) {
    console.error('Chyba při vytváření konverzace:', err);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});

// Získání zpráv
app.get('/api/get-messages', async (req, res) => {
  const { conversationId } = req.query;
  
  try {
    const result = await pool.query(
      `SELECT m.*, 
              CASE 
                WHEN m.sender_id = p.id THEN p.email
                ELSE a.email
              END as sender_email
       FROM messages m
       JOIN conversations c ON m.conversation_id = c.id
       JOIN pilots p ON c.pilot_id = p.id
       JOIN advertisers a ON c.advertiser_id = a.id
       WHERE m.conversation_id = $1
       ORDER BY m.created_at ASC`,
      [conversationId]
    );
    
    res.json(result.rows);
  } catch (err) {
    console.error('Chyba při načítání zpráv:', err);
    res.status(500).json([]);
  }
});

// Odeslání zprávy
app.post('/api/send-message', async (req, res) => {
  const { conversation_id, sender_email, message } = req.body;
  // Validace vstupů
    if (!conversation_id || !sender_email || !message) {
        return res.status(400).json({ error: "Chybějící povinná pole" });
    }

  try {
    // 1. Najdeme ID odesílatele
    let senderId;
    const pilotRes = await pool.query('SELECT id FROM pilots WHERE email = $1', [sender_email]);
    if (pilotRes.rowCount > 0) {
      senderId = pilotRes.rows[0].id;
    } else {
      const inzerentRes = await pool.query('SELECT id FROM advertisers WHERE email = $1', [sender_email]);
      if (inzerentRes.rowCount > 0) {
        senderId = inzerentRes.rows[0].id;
      } else {
        return res.status(404).json({ error: 'Uživatel nenalezen' });
      }
    }
    
    // 2. Ověříme, že konverzace existuje
    const convRes = await pool.query('SELECT 1 FROM conversations WHERE id = $1', [conversation_id]);
    if (convRes.rowCount === 0) {
      return res.status(404).json({ error: 'Konverzace nenalezena' });
    }
    
    // 3. Uložíme zprávu
    const result = await pool.query(
      `INSERT INTO messages (conversation_id, sender_id, message)
       VALUES ($1, $2, $3) RETURNING *, $4 as sender_email`,
      [conversation_id, senderId, message, sender_email]
    );
    
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Chyba při odesílání zprávy:', err);
    res.status(500).json({ error: 'Chyba serveru' });
  }
});
// Najdi nebo vytvoř konverzaci mezi pilotem a inzerentem
// Upravený endpoint pro start konverzace
app.post('/api/start-conversation', async (req, res) => {
  const { pilotEmail, inzerentEmail } = req.body;

  try {
    // 1. Najdi ID obou uživatelů
    const pilot = await pool.query('SELECT id, name FROM pilots WHERE email = $1', [pilotEmail]);
    const inzerent = await pool.query('SELECT id FROM advertisers WHERE email = $1', [inzerentEmail]);

    if (pilot.rowCount === 0 || inzerent.rowCount === 0) {
      return res.status(404).json({ error: 'Uživatelé nenalezeni' });
    }

    const pilotId = pilot.rows[0].id;
    const inzerentId = inzerent.rows[0].id;

    // 2. Zkus najít existující konverzaci
    const existing = await pool.query(
      'SELECT id FROM conversations WHERE pilot_id = $1 AND advertiser_id = $2',
      [pilotId, inzerentId]
    );

    if (existing.rowCount > 0) {
      return res.json({ 
        conversationId: existing.rows[0].id,
        partnerEmail: pilotEmail,
        partnerName: pilot.rows[0].name
      });
    }

    // 3. Vytvoř novou konverzaci
    const newConv = await pool.query(
      `INSERT INTO conversations (pilot_id, advertiser_id) 
       VALUES ($1, $2) RETURNING id`,
      [pilotId, inzerentId]
    );

    res.json({
      conversationId: newConv.rows[0].id,
      partnerEmail: pilotEmail,
      partnerName: pilot.rows[0].name
    });

  } catch (err) {
    console.error('Chyba při vytváření konverzace:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Získání zpráv pro konverzaci
app.get('/api/conversation-messages', async (req, res) => {
  const { conversationId } = req.query;

  try {
    const messages = await pool.query(
      `SELECT m.*, 
              CASE WHEN m.sender_id = p.id THEN p.email ELSE a.email END as sender_email,
              CASE WHEN m.sender_id = p.id THEN p.name ELSE a.name END as sender_name
       FROM messages m
       JOIN conversations c ON m.conversation_id = c.id
       JOIN pilots p ON c.pilot_id = p.id
       JOIN advertisers a ON c.advertiser_id = a.id
       WHERE m.conversation_id = $1
       ORDER BY m.created_at ASC`,
      [conversationId]
    );

    res.json(messages.rows);
  } catch (err) {
    console.error('Chyba při načítání zpráv:', err);
    res.status(500).json([]);
  }
});

async function sendMessage(conversationId, isPilot) {
  const input = document.getElementById('message-input');
  const message = input.value.trim();

  if (!message) return;

  try {
    const response = await fetch('/api/send-message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        conversation_id: conversationId,
        sender_email: currentUserEmail,
        message: message
      })
    });

    const newMessage = await response.json();
    
    // Přidání zprávy do UI
    const messagesContainer = document.getElementById('messages-container');
    const msgElement = document.createElement('div');
    msgElement.className = 'message message-sent';
    msgElement.innerHTML = `
      <div>${newMessage.message}</div>
      <small class="text-muted d-block text-end">
        ${new Date(newMessage.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
      </small>
    `;
    messagesContainer.appendChild(msgElement);
    input.value = '';
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

  } catch (error) {
    console.error('Chyba při odesílání zprávy:', error);
    alert('Nepodařilo se odeslat zprávu');
  }
}



// Spuštění serveru
const PORT = process.env.PORT || 3000;
app.use((err, req, res, next) => {
    console.error('❌ Chyba:', err.stack);
    res.status(500).json({ error: 'Interní chyba serveru' });
});
app.listen(PORT, () => {
  console.log(`Server běží na portu ${PORT}`);
});