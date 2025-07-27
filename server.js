require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');
const { Pool } = require('pg');
const path = require('path');
const prerender = require('prerender-node');

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(prerender);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Registrace
app.post('/register', async (req, res) => {
  const {
    name, email, password, phone, website,
    city, street, zip, region,
    licenses, drones, note, travel
  } = req.body;

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
    console.warn("❗Adresa se nepodařilo geokódovat:", location);
  }
} catch (err) {
  console.error("Chyba při geokódování:", err);
}

  const licenseList = Array.isArray(licenses) ? licenses.join(', ') : (licenses || '');

  try {
    await pool.query(
      `INSERT INTO pilots (
        name, email, phone, website,
        city, street, zip, region,
        licenses, drones, note, travel,
        latitude, longitude, password_hash
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [name, email, phone, website, city, street, zip, region, licenseList, drones, note, travel, lat, lon, password_hash]
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
    const result = await pool.query(`SELECT * FROM pilots`);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
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
  const {
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
    volunteer
  } = req.body;

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
    console.warn("❗Adresa se nepodařilo geokódovat:", location);
  }
} catch (err) {
  console.error("Chyba při geokódování:", err);
}

  try {
    await pool.query(
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
        longitude = $15
      WHERE email = $16`,
      [
        name || "",
        phone || "",
        website || "",
        street || "",
        city || "",
        zip || "",
        region || "",
        drones || "",
        note || "",
        travel || "",
        licenses || "",
        specialization || "",
        volunteer === "ANO" ? "ANO" : "NE",
        lat,
        lon,
        email
      ]
    );

    res.send("✅ Údaje byly úspěšně aktualizovány.");
  } catch (err) {
    console.error("❌ Chyba při aktualizaci:", err);
    res.status(500).send("Chyba při aktualizaci údajů.");
  }
});

app.post('/delete-all', async (req, res) => {
  try {
    await pool.query('DELETE FROM pilots');
    res.send("✅ Všechny záznamy byly smazány.");
  } catch (err) {
    console.error("❌ Chyba při mazání:", err);
    res.status(500).send("Chyba při mazání.");
  }
});

app.post('/delete-selected', async (req, res) => {
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

app.post('/change-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  if (!email || !oldPassword || !newPassword) {
    return res.status(400).send("Chybí některý z požadovaných údajů.");
  }

  try {
    const result = await pool.query('SELECT * FROM pilots WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) return res.status(404).send("Uživatel nenalezen.");

    const isMatch = await bcrypt.compare(oldPassword, user.password_hash);
    if (!isMatch) return res.status(401).send("Staré heslo není správné.");

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE pilots SET password_hash = $1 WHERE email = $2', [newHash, email]);

    res.send("✅ Heslo bylo úspěšně změněno.");
  } catch (err) {
    console.error("❌ Chyba při změně hesla:", err);
    res.status(500).send("Chyba při změně hesla.");
  }
});

// Spuštění serveru
app.listen(port, () => console.log(`Server běží na http://localhost:${port}`));