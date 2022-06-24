const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const connectMongo = require("connect-mongo");
const bodyParser = require("body-parser");
const exphbs = require("express-handlebars");
const path = require("path");
const bcrypt = require("bcrypt");
const User = require("./models/user");
const contenedorMongoose = require("./cont/mongoCont");
const config = require("./config");
const { fork } = require("child_process");
const cluster = require("cluster");
const http = require("http");
const numCPUs = require("os").cpus().length;
const compression = require("express");
const log4js = require("log4js");
const crypto = require("crypto");

const passport = require("passport");
const { Strategy } = require("passport-local");
const LocalStrategy = Strategy;

const app = express();

app.use("/main", express.static(__dirname + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const MongoStore = connectMongo.create({
  mongoUrl: config.KEY,
  ttl: 600,
});

// LOGS

log4js.configure({
  appenders: {
    consola: { type: "console" },
    archivoW: { type: "file", filename: "warnings.log" },
    archivoE: { type: "file", filename: "errors.log" },

    loggerConsola: {
      type: "logLevelFilter",
      appender: "consola",
      level: "info",
    },
    loggerArchivoW: {
      type: "logLevelFilter",
      appender: "archivoW",
      level: "warning",
    },
    loggerArchivoE: {
      type: "logLevelFilter",
      appender: "archivoE",
      level: "error",
    },
  },
  categories: {
    default: {
      appenders: ["loggerConsola"],
      level: "all",
    },
    file: {
      appenders: ["loggerArchivoW"],
      level: "all",
    },
    file2: {
      appenders: ["loggerArchivoE"],
      level: "all",
    },
  },
});

const logger = log4js.getLogger();
const loggerError = log4js.getLogger("file2");
const loggerWarning = log4js.getLogger("file");

// Cluster

// if (cluster.isMaster) {
//   console.log(`I am a master ${process.pid}`);
//   for (let i = 0; i < numCPUs; i++) {
//     cluster.fork();
//   }
//   cluster.on("listening", (worker, address) => {
//     console.log(`${worker.process.pid} es listening in port ${address.port}`);
//   });
// } else {
//   http
//     .createServer((req, res) => {
//       res.writeHead(200);
//       res.end("Hola mundo");
//     })
//     .listen(8000);
//   console.log(`Worker ${process.pid} started`);
// }

// Motor de plantillas
app.set("views", path.join(path.dirname(""), "./src/views"));
app.engine(
  ".hbs",
  exphbs.engine({
    defaultLayout: "main",
    layoutsDir: path.join(app.get("views"), "layouts"),
    extname: ".hbs",
  })
);
app.set("view engine", ".hbs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

//bcrypt

async function createHash(password) {
  const saltRounds = 10;

  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return hash;
  } catch (error) {
    console.log(error);
  }
}

async function verificaPass(usuario, password) {
  const saltRounds = 10;
  console.log("old pass hash: ", usuario.password);
  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);

    console.log("new pass hash: ", hash);
    bcrypt.compare(usuario.password, hash, function (err, result) {
      if (result) {
        console.log("It matches!");
        return true;
      } else {
        console.log("Invalid password!");
        return false;
      }
    });
  } catch (error) {
    console.log(error);
  }
}

//Session
app.use(cookieParser());
app.use(
  session({
    store: MongoStore,
    secret: ".",
    resave: false,
    saveUninitialized: false,
  })
);

//Passport

passport.use(
  new LocalStrategy(async (username, password, done) => {
    const bd = new contenedorMongoose(User);
    let coll = await bd.read().then();
    const existeUsuario = coll.find((usuario) => {
      return usuario.username == username;
    });

    console.log(existeUsuario);

    if (!existeUsuario) {
      console.log("Usuario no encontrado");
      return done(null, false);
    }

    if (await verificaPass(existeUsuario, password)) {
      console.log("Contrase;a invalida");
      return done(null, false);
    }

    return done(null, existeUsuario);
  })
);

passport.serializeUser((usuario, done) => {
  console.log(usuario.username);
  done(null, usuario.username);
});

passport.deserializeUser(async (nombre, done) => {
  const bd = new contenedorMongoose(User);
  let coll = await bd.read().then();
  const usuario = coll.find((usuario) => usuario.username == nombre);
  console.log(usuario);
  done(null, usuario);
});

//Rutas
app.use(compression());

app.get("/", (req, res) => {
  if (req.session.username) {
    res.redirect("/datos");
  } else {
    res.redirect("/login");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/logged",
    failureRedirect: "/loginError",
  })
);

app.get("/loginError", (req, res) => {
  res.render("loginError");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const bd = new contenedorMongoose(User);
  let coll = await bd.read().then();

  const newUsuario = coll.find(
    (usuario) => usuario.username == req.body.username
  );
  if (newUsuario) {
    res.render("registerError");
  } else {
    let newUser = {};
    newUser.username = req.body.username;
    newUser.email = req.body.email;
    newUser.password = await createHash(req.body.password);
    bd.create(req.body);
    res.redirect("/login");
  }
});

app.get("/logged", (req, res) => {
  console.log("logged req.user: ", req);
  console.log("logged req.user: ", req.session.passport.user);
  console.log(req.session.passport);
  const datosUsuario = {
    nombre: req.session.passport.user.username,
    direccion: req.session.passport.user.email,
  };
  res.render("logged", { contador: req.user.contador, datos: datosUsuario });
});

app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

app.get("/info", (req, res) => {
  let inf = [
    process.platform,
    process.version,
    process.memoryUsage(),
    process.cwd(),
    process.pid,
  ];
  logger.info("");
  loggerWarning.warn();
  loggerError.error();
  console.log(inf);
});

app.get("/api/randoms/:max", (req, res) => {
  const ran = fork("child.js");

  ran.on("message", (msg) => {
    if (msg == "listo") {
      ran.send(req.params.max);
    } else {
      res.send(msg);
    }
  });
});
const users = {};
app.get("/newUser", (req, res) => {
  let username = req.query.username || "";
  const password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g, "");

  if (!username || !password || users[username]) {
    return res.sendStatus(400);
  }

  const salt = crypto.randomBytes(128).toString("base64");
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 512, "sha512");

  users[username] = { salt, hash };
  console.log("Success");
  res.sendStatus(200);
});
app.get("/auth-bloq", (req, res) => {
  let username = req.query.username || "";
  const password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g, "");

  if (!username || !password || !users[username]) {
    process.exit(1);
    return res.sendStatus(400);
  }

  const { salt, hash } = users[username];
  const encryptHash = crypto.pbkdf2Sync(password, salt, 10000, 512, "sha512");

  if (crypto.timingSafeEqual(hash, encryptHash)) {
    res.sendStatus(200);
  } else {
    process.exit(1);
    res.sendStatus(401);
  }
});

const PORT = config.PORT;
app.listen(8080, () => {
  console.log(`Servidor express escuchando en el puerto ${PORT}`);
});
