const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 10009;

app.use(bodyParser.urlencoded({ extended: true }));

const key = "randomBytes(16).toString('hex')";

const htmlPage = (result = '') => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Flag Vault</title>
  <style>
    * {
      box-sizing: border-box;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin: 0;
      padding: 0;
    }
    body {
      background-color: #0d0d0d;
      color: #e5e5e5;
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
    }
    .container {
      width: 100%;
      max-width: 420px;
      padding: 2rem;
    }
    h1 {
      font-size: 1.5rem;
      color: #ffffff;
      margin-bottom: 1rem;
      text-align: center;
    }
    p {
      font-size: 0.9rem;
      color: #b3b3b3;
      margin-bottom: 1.5rem;
      text-align: center;
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }
    input {
      background-color: #1a1a1a;
      color: #e5e5e5;
      border: 1px solid #333;
      border-radius: 4px;
      padding: 0.6rem 0.9rem;
      font-size: 0.95rem;
    }
    input::placeholder {
      color: #666;
    }
    button {
      background-color: #262626;
      color: #e5e5e5;
      border: 1px solid #333;
      border-radius: 4px;
      padding: 0.6rem 0.9rem;
      font-size: 0.95rem;
      cursor: pointer;
      transition: background-color 0.2s ease;
    }
    button:hover {
      background-color: #333333;
    }
    pre {
      background-color: #1a1a1a;
      color: #cccccc;
      padding: 1rem;
      margin-top: 1.5rem;
      border-radius: 4px;
      font-size: 0.9rem;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Flag Vault</h1>
    <p>Enter the exact key to unlock the flag</p>
    <form method="POST" action="/search">
      <input name="query" placeholder="Paste your key here..." required />
      <button type="submit">Unlock</button>
    </form>
    <pre>${result}</pre>
  </div>
</body>
</html>
`;



app.get('/', (req, res) => {
  res.send(htmlPage());
});

app.post('/search', (req, res) => {
  const query = req.body.query;

  if (query.includes("String")) {
    return res.send(htmlPage("❌ Access Denied: Suspicious pattern detected."));
  }

  if (query.includes(key)) {
    return res.send(htmlPage("✅ Key matched: " + query + "\n🎉 Here is your flag: prelim{not the flag, anw i love teh ais :D}"));
  } else {
    return res.send(htmlPage("❌ Key did not match."));
  }
});

app.listen(port, () => {
  console.log(`🚀 Challenge running at http://localhost:${port}`);
});