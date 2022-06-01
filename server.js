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

const passport = require("passport");
const { Strategy } = require("passport-local");
const LocalStrategy = Strategy;

const app = express();

app.use("/main", express.static(__dirname + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const MongoStore = connectMongo.create({
  mongoUrl:
    "mongodb+srv://ferru:ferru2647@cluster0.lpvnv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority",
  ttl: 600,
});

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
    nombre: req.user.username,
    direccion: req.user.email,
  };
  res.render("logged", { contador: req.user.contador, datos: datosUsuario });
});

app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Servidor express escuchando en el puerto ${PORT}`);
});
