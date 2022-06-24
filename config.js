require("dotenv").config();
const parseArgs = require("minimist");

function param(p) {
  const index = process.argv.indexOf(p);
  return process.argv[index + 1];
}
const port = param("--port");
// console.log(process.env.PORT);
// console.log(port || process.env.PORT);

module.exports = {
  KEY: process.env.KEY,
  PORT: port || process.env.PORT,
};
