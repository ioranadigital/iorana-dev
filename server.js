// ══════════════════════════════════════════════════════════
//  iorana.dev — Servidor de autenticación segura
//  Node.js + Express + Redis (sesiones persistentes)
// ══════════════════════════════════════════════════════════

require("dotenv").config();

const express               = require("express");
const session               = require("express-session");
const bcrypt                = require("bcryptjs");
const helmet                = require("helmet");
const path                  = require("path");
const { createClient }      = require("redis");
const { RedisStore }        = require("connect-redis");
const { RateLimiterMemory } = require("rate-limiter-flexible");

const app  = express();
const PORT = process.env.PORT || 3000;

// ══════════════════════════════════════════════════════════
//  REDIS — cliente con reconexión automática
// ══════════════════════════════════════════════════════════
const redisClient = createClient({
  url:    process.env.REDIS_URL || "redis://localhost:6379",
  socket: {
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        console.error("✗  Redis: demasiados reintentos. Abortando.");
        return new Error("Redis no disponible");
      }
      // Espera exponencial: 100ms, 200ms, 400ms… hasta 3s
      return Math.min(retries * 100, 3000);
    },
  },
});

redisClient.on("connect",      () => console.log("✓  Redis: conectado"));
redisClient.on("reconnecting", () => console.log("⟳  Redis: reconectando…"));
redisClient.on("error", (err)  => console.error("✗  Redis error:", err.message));

// ── Arrancar Redis antes de levantar el servidor ──────────
(async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    console.error("✗  No se pudo conectar a Redis:", err.message);
    console.warn("⚠️  Las sesiones no persistirán entre reinicios.");
  }

  // ══════════════════════════════════════════════════════════
  //  RATE LIMITER — max 5 intentos / IP / 15 min
  // ══════════════════════════════════════════════════════════
  const rateLimiter = new RateLimiterMemory({
    points:   5,
    duration: 15 * 60,
  });

  // ══════════════════════════════════════════════════════════
  //  HELMET — cabeceras de seguridad
  // ══════════════════════════════════════════════════════════
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc:  ["'self'", "'unsafe-inline'"],
          styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc:    ["'self'", "https://fonts.gstatic.com"],
          imgSrc:     ["'self'", "data:"],
          connectSrc: ["'self'"],
          frameSrc:   ["'none'"],
        },
      },
      referrerPolicy: { policy: "no-referrer" },
    })
  );

  // X-Robots-Tag en TODAS las respuestas
  app.use((req, res, next) => {
    res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
    next();
  });

  // ══════════════════════════════════════════════════════════
  //  PARSERS
  // ══════════════════════════════════════════════════════════
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // ══════════════════════════════════════════════════════════
  //  SESIONES — almacenadas en Redis
  // ══════════════════════════════════════════════════════════
  const redisStore = new RedisStore({
    client:       redisClient,
    prefix:       "iorana:sess:",   // namespace en Redis
    ttl:          8 * 60 * 60,     // 8 horas en segundos
    disableTouch: false,            // renueva TTL en cada petición
  });

  app.use(
    session({
      store:             redisStore,
      secret:            process.env.SESSION_SECRET || "cambia-este-secreto-en-produccion",
      resave:            false,
      saveUninitialized: false,
      name:              "iorana.sid",
      cookie: {
        httpOnly: true,
        secure:   process.env.NODE_ENV === "production",  // solo HTTPS en prod
        sameSite: "strict",
        maxAge:   8 * 60 * 60 * 1000,   // 8 horas en ms
      },
    })
  );

  // ══════════════════════════════════════════════════════════
  //  MIDDLEWARE — protección de rutas
  // ══════════════════════════════════════════════════════════
  function requireAuth(req, res, next) {
    if (req.session?.authenticated) return next();
    if (req.accepts("html"))        return res.redirect("/");
    return res.status(401).json({ error: "No autenticado" });
  }

  // ══════════════════════════════════════════════════════════
  //  RUTAS PÚBLICAS
  // ══════════════════════════════════════════════════════════

  // GET / — página de login
  app.get("/", (req, res) => {
    if (req.session?.authenticated) return res.redirect("/portal");
    res.sendFile(path.join(__dirname, "public", "index.html"));
  });

  // POST /auth/login
  app.post("/auth/login", async (req, res) => {
    const ip = req.ip;

    // 1. Rate limit
    try {
      await rateLimiter.consume(ip);
    } catch {
      return res.status(429).json({
        success: false,
        error:   "Demasiados intentos. Espera 15 minutos.",
      });
    }

    const { password } = req.body;
    if (!password || typeof password !== "string") {
      return res.status(400).json({ success: false, error: "Contraseña requerida." });
    }

    // 2. Verificar con bcrypt
    const storedHash = process.env.PASSWORD_HASH;
    const match      = await bcrypt.compare(password, storedHash);

    if (!match) {
      await new Promise(r => setTimeout(r, 300));   // anti timing-attack
      return res.status(401).json({ success: false, error: "Contraseña incorrecta." });
    }

    // 3. Regenerar sesión (previene session fixation)
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ success: false, error: "Error de sesión." });
      req.session.authenticated = true;
      req.session.loginAt       = new Date().toISOString();
      req.session.ip            = ip;
      rateLimiter.reward(ip);
      return res.json({ success: true, redirect: "/portal" });
    });
  });

  // POST /auth/logout
  app.post("/auth/logout", (req, res) => {
    req.session.destroy(() => {
      res.clearCookie("iorana.sid");
      res.json({ success: true });
    });
  });

  // GET /auth/check
  app.get("/auth/check", (req, res) => {
    res.json({ authenticated: !!req.session?.authenticated });
  });

  // GET /auth/sessions — sesiones activas en Redis (admin)
  app.get("/auth/sessions", requireAuth, async (req, res) => {
    try {
      const keys  = await redisClient.keys("iorana:sess:*");
      res.json({ activeSessions: keys.length, keys });
    } catch {
      res.status(500).json({ error: "No se pudo consultar Redis" });
    }
  });

  // ── robots.txt ────────────────────────────────────────────
  app.get("/robots.txt", (req, res) => {
    res.type("text/plain");
    res.send("User-agent: *\nDisallow: /\n");
  });

  // ══════════════════════════════════════════════════════════
  //  RUTAS PROTEGIDAS
  // ══════════════════════════════════════════════════════════
  app.get("/portal", requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "portal.html"));
  });

  app.use("/assets", requireAuth, express.static(path.join(__dirname, "public", "assets")));

  // ── 404 catch-all ─────────────────────────────────────────
  app.use((req, res) => {
    if (req.session?.authenticated) return res.redirect("/portal");
    res.redirect("/");
  });

  // ══════════════════════════════════════════════════════════
  //  ARRANQUE
  // ══════════════════════════════════════════════════════════
  app.listen(PORT, () => {
    console.log(`\n✓  iorana.dev corriendo en http://localhost:${PORT}`);
    console.log(`   Entorno : ${process.env.NODE_ENV || "development"}`);
    console.log(`   Redis   : ${process.env.REDIS_URL || "redis://localhost:6379"}`);
    console.log(`   Sesiones: Redis (iorana:sess:*)\n`);
  });

  // ── Cierre limpio ──────────────────────────────────────────
  const shutdown = async (signal) => {
    console.log(`\n${signal} recibido. Cerrando…`);
    await redisClient.quit();
    process.exit(0);
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT",  () => shutdown("SIGINT"));
})();
