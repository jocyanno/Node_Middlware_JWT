const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");

const app = express();
const crypto = require("crypto");
const chaveSecreta = crypto.randomBytes(32).toString("hex");

const dbConfig = {
  host: "localhost",
  user: "root",
  password: "",
  database: "user"
};

// Middleware para autenticação do token
app.use(express.json());

function autenticarToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ mensagem: "Token não fornecido." });
  }

  jwt.verify(token, chaveSecreta, (erro, dadosDecodificados) => {
    if (erro) {
      return res.status(403).json({ mensagem: "Token inválido." });
    }

    req.usuario = dadosDecodificados;
    next();
  });
}

// Rota protegida
app.get("/dados-protegidos", autenticarToken, async (req, res) => {
  try {
    // Conectar ao banco de dados
    const conexao = await mysql.createConnection(dbConfig);

    // Executar consulta no banco de dados
    const [rows] = await conexao.query("SELECT * FROM users");

    // Fechar a conexão com o banco de dados
    conexao.end();

    res.json({ dados: rows });
  } catch (erro) {
    console.error("Erro ao acessar o banco de dados:", erro);
    res.status(500).json({ mensagem: "Erro ao acessar o banco de dados." });
  }
});

// Rota protegida
app.get("/dados-protegidos", autenticarToken, async (req, res) => {
  try {
    // Conectar ao banco de dados
    const conexao = await mysql.createConnection(dbConfig);

    // Executar consulta no banco de dados
    const [rows] = await conexao.query("SELECT * FROM regiao");

    // Fechar a conexão com o banco de dados
    conexao.end();

    res.json({ dados: rows });
  } catch (erro) {
    console.error("Erro ao acessar o banco de dados:", erro);
    res.status(500).json({ mensagem: "Erro ao acessar o banco de dados." });
  }
});

// Rota de autenticação
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Conectar ao banco de dados
    const conexao = await mysql.createConnection(dbConfig);

    // Consultar o usuário no banco de dados
    const [rows] = await conexao.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );
    const usuario = rows[0];

    // Verificar se o usuário existe e a senha está correta
    if (!usuario || usuario.password !== password) {
      return res.status(401).json({ mensagem: "Credenciais inválidas." });
    }

    // Gerar o token
    const token = jwt.sign(
      { id: usuario.id, username: usuario.username },
      chaveSecreta,
      { expiresIn: "1h" }
    );

    // Fechar a conexão com o banco de dados
    conexao.end();

    res.json({ token });
  } catch (erro) {
    console.error("Erro ao acessar o banco de dados:", erro);
    res.status(500).json({ mensagem: "Erro ao acessar o banco de dados." });
  }
});

// Iniciar o servidor
app.listen(3000, () => {
  console.log("Servidor rodando na porta 3000");
});
