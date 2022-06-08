process.on("message", (msg) => {
  let lista = [{ num: 0, rep: 0 }];
  let maxNum;
  if (!msg) {
    maxNum = 100000000;
  } else {
    maxNum = msg;
  }
  for (let i = 0; i < maxNum; i++) {
    let numA = Math.floor(Math.random() * maxNum);
    let found = lista.some((el) => el.num === numA);
    if (!found) {
      lista.push({ num: numA, rep: 1 });
    }
    if (found) {
      let foundIndex = lista.findIndex((x) => x.num == numA);
      //   console.log(lista[foundIndex].rep);
      lista[foundIndex].rep++;
    }
  }
  //   console.log(`mensaje del padre: ${msg}`);
  console.log(msg);
  process.send(lista);
  process.exit();
});

process.send("listo");
