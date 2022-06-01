const mongoose = require("mongoose");
const { user } = require("../models/user.js");

CRUD();

async function CRUD() {
  try {
    mongoose.connect(
      "mongodb+srv://ferru:ferru2647@cluster0.lpvnv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log("Conectado a MongoDB");
  } catch (err) {
    console.log(err);
  }
}

class contenedorMongoose {
  constructor(ruta) {
    this.ruta = ruta;
  }

  async create(newProd) {
    const productoNuevo = new this.ruta(newProd);
    const productos = await this.ruta.find();
    productoNuevo.id = productos.length + 1;
    await productoNuevo.save();
    console.log(productoNuevo);
  }

  async read() {
    const productos = await this.ruta.find();
    return productos;
  }

  async update(query, change) {
    const que = {};
    que._id = query;
    const productoUpdate = await this.ruta.findOneAndUpdate(que, change);
    console.log(productoUpdate);
  }

  async delete(query) {
    console.log(this.ruta);
    const que = {};
    que._id = query;
    const productoDelete = await this.ruta.deleteOne(que);
    console.log(productoDelete);
  }
}

const lista = [
  { title: "prod1", price: 50, stock: 20 },
  { title: "prod2", price: 30, stock: 15 },
  { title: "prod3", price: 20, stock: 10 },
];

module.exports = contenedorMongoose;
