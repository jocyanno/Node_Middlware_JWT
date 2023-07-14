const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const chaveSecreta = crypto.randomBytes(32).toString('hex');

const app = express();

const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'users',
};

// Middleware para autenticação do token
function autenticarToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ mensagem: 'Token não fornecido.' });
  }

  jwt.verify(token, chaveSecreta, (erro, dadosDecodificados) => {
    if (erro) {
      return res.status(403).json({ mensagem: 'Token inválido.' });
    }

    req.usuario = dadosDecodificados;
    next();
  });
}

// Rota protegida
app.get('/dados-protegidos', autenticarToken, async (req, res) => {
  try {
    // Conectar ao banco de dados
    const conexao = await mysql.createConnection(dbConfig);

    // Executar consulta no banco de dados
    const [rows] = await conexao.query('SELECT * FROM regiao');

    // Fechar a conexão com o banco de dados
    conexao.end();

    res.json({ dados: rows });
  } catch (erro) {
    console.error('Erro ao acessar o banco de dados:', erro);
    res.status(500).json({ mensagem: 'Erro ao acessar o banco de dados.' });
  }
});

// Rota de autenticação
app.post('/login', (req, res) => {
  // Aqui você deve fazer a autenticação do usuário e gerar o token
  // Vamos apenas simular um login básico para fins de exemplo
  const usuario = {
    id: 123,
    nome: 'Exemplo'
  };

  const token = jwt.sign(usuario, chaveSecreta, { expiresIn: '1h' });

  res.json({ token });
});

// Iniciar o servidor
app.listen(3000, () => {
  console.log('Servidor rodando na porta 3000');
});
