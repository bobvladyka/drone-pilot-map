const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const sharp = require("sharp");
const { exec } = require("child_process");

const router = express.Router();

// =======================================================
// ✅ CESTY
// =======================================================
const BLOG_DIR = path.join(__dirname, "..", "public", "blogposts");
const IMG_DIR  = path.join(__dirname, "..", "public", "blogposts_img");
const META_DIR = path.join(__dirname, "..", "blogposts_meta");
if (!fs.existsSync(META_DIR)) fs.mkdirSync(META_DIR);


// =======================================================
// ✅ MULTER (UPLOAD OBRÁZKU)
// =======================================================
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fieldSize: 25 * 1024 * 1024 }
});

// =======================================================
// ✅ ZÁVISLOSTI ZE SERVER.JS (INJECTION)
// =======================================================
let requireAdminLogin;


// =======================================================
// ✅ INIT FUNKCE – NAPOJENÍ ZE SERVER.JS
// =======================================================
function initBlogRoutes(deps) {
  requireAdminLogin   = deps.requireAdminLogin;
  
}

/**
 * Vytvoří kompletní HTML kód blogového článku podle šablony.
 */
function generateArticleHtml(slug, data) {
  const pubDate = new Date().toLocaleDateString('cs-CZ', { 
    day: 'numeric', 
    month: 'long', 
    year: 'numeric' 
  });

  const url = `https://www.najdipilota.cz/blogposts/${slug}.html`;
  const heroUrl = `/blogposts_img/${slug}-hero.webp`;

  const processedBodyHtml = prepareSocialButtonsInContent(
    data.bodyHtml,
    slug,
    data.title,
    url
  );

  return `
<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${data.title} | NajdiPilota.cz</title>

  <meta name="description" content="${data.description}" />
  <meta name="robots" content="index, follow" />
  <link rel="canonical" href="${url}" />

  <meta property="og:title" content="${data.title} | NajdiPilota.cz" />
  <meta property="og:description" content="${data.description}" />
  <meta property="og:url" content="${url}" />
  <meta property="og:type" content="article" />
  <meta property="og:image" content="https://www.najdipilota.cz${heroUrl}" />

  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="${data.title}" />
  <meta name="twitter:description" content="${data.description}" />
  <meta name="twitter:image" content="https://www.najdipilota.cz${heroUrl}" />

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" />
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
  <link rel="stylesheet" href="/style.css?v=77" />
</head>
<body>

<div class="container py-5">
  <div class="row justify-content-center">
    <div class="col-lg-8">

      <a href="/blog.html" class="text-primary fw-bold small text-decoration-none">
        <i class="bi bi-arrow-left"></i> Zpět na blog
      </a>

      <h1 class="mt-3 fw-bold">${data.title}</h1>

      <p class="article-meta">
        Publikováno: ${pubDate} |
        Kategorie: ${data.category} |
        Autor: ${data.author}
      </p>

      <img src="${heroUrl}" class="main-image" alt="Hlavní obrázek článku">

      <div class="blog-content fs-5">
        ${processedBodyHtml}
        ${addSocialSharingBlockIfMissing(processedBodyHtml, slug, data.title, url)}
      </div>

    </div>
  </div>
</div>

<script>
function copyArticleUrl(url) {
  navigator.clipboard.writeText(url);
}
</script>

</body>
</html>`;
}

/**
 * Zpracuje HTML obsah a nahradí data- atributy pro sdílení skutečnými odkazy
 */
function prepareSocialButtonsInContent(html, slug, title, url) {
  const encodedUrl = encodeURIComponent(url);
  const encodedTitle = encodeURIComponent(title);

  html = html.replace(
    /href="#" data-share-type="facebook"[^>]*>/gi,
    `href="https://www.facebook.com/sharer/sharer.php?u=${encodedUrl}&quote=${encodedTitle}" target="_blank" class="social-btn facebook">`
  );

  html = html.replace(
    /href="#" data-share-type="linkedin"[^>]*>/gi,
    `href="https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}" target="_blank" class="social-btn linkedin">`
  );

  html = html.replace(
    /<button[^>]*data-copy-url="[^"]*"[^>]*>/gi,
    `<button onclick="copyArticleUrl('${url}')" class="social-btn copy">`
  );

  return html;
}

/**
 * Pokud v článku není blok sdílení, automaticky jej přidá
 */
function addSocialSharingBlockIfMissing(html, slug, title, url) {
  if (html.includes('social-sharing-section')) return '';

  const encodedUrl = encodeURIComponent(url);
  const encodedTitle = encodeURIComponent(title);

  return `
<div class="social-sharing-section mt-5 pt-4 border-top">
  <h4>📢 Sdílejte tento článek</h4>
  <div class="social-buttons-container">
    <a href="https://www.facebook.com/sharer/sharer.php?u=${encodedUrl}&quote=${encodedTitle}" target="_blank" class="social-btn facebook">Facebook</a>
    <a href="https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}" target="_blank" class="social-btn linkedin">LinkedIn</a>
    <button onclick="copyArticleUrl('${url}')" class="social-btn copy">Kopírovat odkaz</button>
  </div>
</div>`;
}


// =======================================================
// ✅ GIT AUTOMATIZACE
// =======================================================
function runGitCommands(slug) {
  console.log("🔄 Spouštím Git automatizaci...");

  exec(`git add public/blogposts/* public/blogposts_img/*`, (err) => {
    if (err) return console.error("Git add error:", err);

    exec(`git commit -m "AUTO: nový blogpost ${slug}"`, (err) => {
      if (err) {
        console.log("ℹ️ Žádné nové změny k commitnutí.");
        return;
      }

      exec(`git push origin main`, (err) => {
        if (err) return console.error("Git push error:", err);
        console.log("🚀 Blogpost automaticky commitnut a pushnut.");
      });
    });
  });
}

// =======================================================
// ✅ POST: CREATE BLOG POST (ADMIN)
// =======================================================
router.post("/api/admin/create-blog-post",
  (req, res, next) => requireAdminLogin(req, res, next),
  upload.single("heroImage"),
  async (req, res) => {
    try {
      const { title, description, bodyHtml, category, author, slug, status, publishAt } = req.body;


      // ✅ VALIDACE
      if (!title || !bodyHtml || !slug) {
        return res.status(400).json({ error: "Chybí titulek, slug nebo obsah." });
      }

      // ===================================================
      // ✅ 1. ZPRACOVÁNÍ OBRÁZKU
      // ===================================================
      if (req.file) {
        const imageFilename = `${slug}-hero.webp`;
        const imagePath = path.join(IMG_DIR, imageFilename);

        await sharp(req.file.buffer)
          .resize({ width: 1200, withoutEnlargement: true }) 
          .webp({ quality: 80 })
          .toFile(imagePath);

        console.log(`📸 Obrázek uložen: ${imageFilename}`);
      }

      // ===================================================
      // ✅ 2. GENEROVÁNÍ HTML
      // ===================================================
      const articleData = {
        title,
        description: description || "",
        bodyHtml,
        category: category || "Nezařazeno",
        author: author || "Tým NajdiPilota"
      };

      const finalHtmlContent = generateArticleHtml(slug, articleData);
      const filename = `${slug}.html`;
      const filePath = path.join(BLOG_DIR, filename);

      fs.writeFileSync(filePath, finalHtmlContent, "utf8");

      // ===================================================
      // ✅ 3. ULOŽENÍ META DAT
      // ===================================================
const metaData = {
  title,
  slug,
  status: status || "published",
  publishAt: publishAt || null,
  createdAt: new Date().toISOString()
};

fs.writeFileSync(
  path.join(META_DIR, `${slug}.json`),
  JSON.stringify(metaData, null, 2)
);

     // ===================================================
     // ✅ 4. GIT PUSH – JEN POKUD JE PUBLIKOVÁNO
     // ===================================================
if (metaData.status === "published") {
  runGitCommands(slug);
}

res.json({ 
  success: true,
  filename,
  url: `/blogposts/${filename}`
});

    } catch (err) {
      console.error("❌ BLOG ERROR:", err);
      res.status(500).json({ error: err.message });
    }
  }
);

// ---------------------------------------------------------------------
// BLOG
// ---------------------------------------------------------------------
router.get("/blog-list", (req, res) => {
  try {
    const files = fs.readdirSync(BLOG_DIR).filter(f => f.endsWith(".html"));

    const posts = files.map(filename => {
      const fullPath = path.join(BLOG_DIR, filename);
      const html = fs.readFileSync(fullPath, "utf8");

      const slug = filename.replace(".html", "");

      const titleMatch = html.match(/<h1[^>]*>(.*?)<\/h1>/);
      const title = titleMatch ? titleMatch[1] : "Bez názvu";

      const descMatch = html.match(/<meta name="description" content="(.*?)"/);
      const description = descMatch ? descMatch[1] : "";

      const dateMatch = html.match(/Publikováno:\s*(.*?)\s*\|/);
      const date = dateMatch ? dateMatch[1] : "";

      const catMatch = html.match(/Kategorie:\s*(.*?)\s*\|/);
      const category = catMatch ? catMatch[1] : "";

      const authorMatch = html.match(/Autor:\s*(.*?)<\/p>/);
      const author = authorMatch ? authorMatch[1] : "NajdiPilota";

      const image = `/blogposts_img/${slug}-hero.webp`;

      return { title, description, image, date, category, author, slug };
    });

    posts.sort((a, b) => b.slug.localeCompare(a.slug));

    res.json(posts);

  } catch (err) {
    console.error("Blog error:", err);
    res.status(500).json({ error: "Cannot load blog posts" });
  }
});

// Pomocná funkce: Získání nových blogových příspěvků za poslední týden
// POZNÁMKA: Využívá předpoklad, že slug začíná YYYYMMDD (např. 20251127-nazev)
async function getNewBlogPosts(sinceDate) {
    const files = fs.readdirSync(BLOG_DIR).filter(f => f.endsWith(".html"));
    const newPosts = [];

    files.forEach(filename => {
        const slug = filename.replace(".html", "");
        const dateStr = slug.substring(0, 8); 
        const year = dateStr.substring(0, 4);
        const month = dateStr.substring(4, 6);
        const day = dateStr.substring(6, 8);
        
        const postDate = new Date(`${year}-${month}-${day}`);

        if (postDate > sinceDate) {
            const fullPath = path.join(BLOG_DIR, filename);
            const html = fs.readFileSync(fullPath, "utf8");
            
            // Extrahujeme Title a Description z HTML souboru (jako v blog-list)
            const titleMatch = html.match(/<h1[^>]*>(.*?)<\/h1>/);
            const descMatch = html.match(/<meta name="description" content="(.*?)"/);

            newPosts.push({
                title: titleMatch ? titleMatch[1] : "Bez názvu",
                description: descMatch ? descMatch[1] : "",
                slug: slug,
                image: `/blogposts_img/${slug}-hero.webp`,
                date: postDate.toLocaleDateString('cs-CZ')
            });
        }
    });

    // Nejnovější články nahoru
    newPosts.sort((a, b) => b.slug.localeCompare(a.slug));
    return newPosts;
}

// =======================================================
// ✅ ADMIN: PŘEHLED ČLÁNKŮ
// =======================================================
router.get(
  "/api/admin/blog-list",
  (req, res, next) => requireAdminLogin(req, res, next),
  (req, res) => {
    const files = fs.readdirSync(META_DIR).filter(f => f.endsWith(".json"));
    const posts = files.map(f =>
      JSON.parse(fs.readFileSync(path.join(META_DIR, f)))
    );
    res.json(posts);
  }
);

// =======================================================
// ✅ ADMIN: SMAZÁNÍ ČLÁNKU
// =======================================================
router.delete(
  "/api/admin/delete/:slug",
  (req, res, next) => requireAdminLogin(req, res, next),
  (req, res) => {
    const { slug } = req.params;

    const htmlPath = path.join(BLOG_DIR, `${slug}.html`);
    const imgPath  = path.join(IMG_DIR, `${slug}-hero.webp`);
    const metaPath = path.join(META_DIR, `${slug}.json`);

    if (fs.existsSync(htmlPath)) fs.unlinkSync(htmlPath);
    if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    if (fs.existsSync(metaPath)) fs.unlinkSync(metaPath);


    runGitCommands(slug);
    res.json({ success: true });
  }
);

// =======================================================
// ✅ ADMIN: OKAMŽITÉ PUBLIKOVÁNÍ
// =======================================================
router.post(
  "/api/admin/publish/:slug",
  (req, res, next) => requireAdminLogin(req, res, next),
  (req, res) => {
    const { slug } = req.params;
    const metaPath = path.join(META_DIR, `${slug}.json`);
    const meta = JSON.parse(fs.readFileSync(metaPath));

    meta.status = "published";
    meta.publishAt = new Date().toISOString();

    fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2));
    runGitCommands(slug);

    res.json({ success: true });
  }
);

// =======================================================
// ✅ CRON: AUTOMATICKÉ VYDÁNÍ NAPLÁNOVANÝCH ČLÁNKŮ
// =======================================================
setInterval(() => {
  const files = fs.readdirSync(META_DIR).filter(f => f.endsWith(".json"));

  files.forEach(file => {
    const data = JSON.parse(fs.readFileSync(path.join(META_DIR, file)));

    if (
  data.status === "scheduled" &&
  data.publishAt &&
  new Date(data.publishAt) <= new Date()
) {
      data.status = "published";
      fs.writeFileSync(
        path.join(META_DIR, file),
        JSON.stringify(data, null, 2)
      );
      runGitCommands(data.slug);
      console.log("✅ Automaticky publikováno:", data.slug);
    }
  });
}, 60000);



// =======================================================
// ✅ ADMIN BLOG PAGE (CHRÁNĚNÁ)
// =======================================================
router.get(
  "/admin-blog-create.html",
  (req, res, next) => requireAdminLogin(req, res, next),
  (req, res) => {
    res.sendFile(path.join(__dirname, "..", "private", "admin-blog-create.html"));
  }
);

// =======================================================
// ✅ ADMIN: EDITACE ČLÁNKU – STRÁNKA
// =======================================================
router.get(
  "/admin-blog-edit.html",
  (req, res, next) => requireAdminLogin(req, res, next),
  (req, res) => {
    res.sendFile(
      path.join(__dirname, "..", "private", "admin-blog-edit.html")
    );
  }
);


// =======================================================
// ✅ ADMIN: NAČTENÍ ČLÁNKU PRO EDITACI
// =======================================================
router.get(
  "/api/admin/blog/:slug",
  (req, res, next) => requireAdminLogin(req, res, next),
  (req, res) => {
    const { slug } = req.params;

    const htmlPath = path.join(BLOG_DIR, `${slug}.html`);
    const metaPath = path.join(META_DIR, `${slug}.json`);

    if (!fs.existsSync(htmlPath) || !fs.existsSync(metaPath)) {
      return res.status(404).json({ error: "Článek nenalezen" });
    }

    const html = fs.readFileSync(htmlPath, "utf8");
    const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));

    res.json({ html, meta });
  }
);

// =======================================================
// ✅ ADMIN: ULOŽENÍ UPRAVENÉHO ČLÁNKU
// =======================================================
router.post(
  "/api/admin/update/:slug",
  (req, res, next) => requireAdminLogin(req, res, next),
  upload.single("heroImage"),
  async (req, res) => {
    try {
      const { slug } = req.params;
      const { title, description, bodyHtml, category, author, status, publishAt } = req.body;

      const htmlPath = path.join(BLOG_DIR, `${slug}.html`);
      const metaPath = path.join(META_DIR, `${slug}.json`);

      if (req.file) {
        await sharp(req.file.buffer)
          .resize({ width: 1200, withoutEnlargement: true })
          .webp({ quality: 80 })
          .toFile(path.join(IMG_DIR, `${slug}-hero.webp`));
      }

      const articleData = {
        title,
        description: description || "",
        bodyHtml,
        category,
        author
      };

      const finalHtmlContent = generateArticleHtml(slug, articleData);
      fs.writeFileSync(htmlPath, finalHtmlContent, "utf8");

      const metaData = {
        title,
        slug,
        status,
        publishAt: publishAt || null,
        updatedAt: new Date().toISOString()
      };

      fs.writeFileSync(metaPath, JSON.stringify(metaData, null, 2));

      if (status === "published") {
        runGitCommands(slug);
      }

      res.json({ success: true });

    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);


module.exports = {
  router,
  initBlogRoutes
};

router.get(
  "/admin-blog-list.html",
  (req, res, next) => requireAdminLogin(req, res, next),
  (req, res) => {
    res.sendFile(path.join(__dirname, "..", "private", "admin-blog-list.html"));
  }
);

