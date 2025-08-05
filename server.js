require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');
const { Pool } = require('pg');
const path = require('path');
const prerender = require('prerender-node');
const session = require('express-session');

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

// Admin route protection middleware
function requireAdminLogin(req, res, next) {
    if (req.session && req.session.isAdmin) {
        return next();
    }
    return res.redirect('/adminland.html');
}

app.use(express.static(path.join(__dirname, 'public')));

app.use(prerender);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.get('/admin.html', requireAdminLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

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


   let visible_valid = new Date();
  visible_valid.setMonth(visible_valid.getMonth() + 1);

  if (ref) {
    try {
      const refResult = await pool.query(
        `UPDATE pilots 
         SET visible_valid = 
           CASE 
             WHEN visible_valid IS NULL THEN CURRENT_DATE + INTERVAL '1 month'
             ELSE visible_valid + INTERVAL '1 month'
           END
         WHERE email = $1
         RETURNING email`,
        [ref]
      );

      if (refResult.rowCount > 0) {
        console.log(`🎉 Připsán měsíc pilotovi, který pozval: ${ref}`);
      }
    } catch (err) {
      console.warn("⚠️ Nepodařilo se připsat bonus referrerovi:", err);
    }
  }

   try {
    await pool.query(
      `INSERT INTO pilots (
        name, email, password_hash, phone, street, city, zip, region,
        latitude, longitude, visible_valid, ref_by_email
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [name, email, password_hash, phone, street, city, zip, region,
       lat, lon, visible_valid, ref || null]
    );

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
    console.log('První záznam z DB:', result.rows[0]); // Debug
    res.json(result.rows);
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
      if (specialization) {
        specialization = specialization.split(",")[0]; // jen první specializace
      }
    }

    // Převod visible na ANO/NE
    visible = visible ? "ANO" : "NE";

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

// Spuštění serveru
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server běží na portu ${PORT}`);
});