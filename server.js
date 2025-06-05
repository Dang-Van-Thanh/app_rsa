const express = require("express");
const forge = require("node-forge");
const bodyParser = require("body-parser");
const path = require("path");
const fs = require("fs");
const crypto = require('crypto');
const multer = require("multer");
const upload = multer({ dest: "uploads/" });



const app = express();
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Bộ nhớ tạm người dùng (chạy lại server sẽ mất)
const users = {}; // { username: { password, publicKey, privateKey } }

// Trang chủ
app.get("/", (req, res) => {
  res.render("index");
});

// Xử lý đăng ký & đăng nhập
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!users[username]) {
    users[username] = { password };
    return res.render("dashboard", { username, publicKey: null });
  }

  if (users[username].password !== password) {
    return res.send("Sai mật khẩu!");
  }

  res.render("dashboard", {
    username,
    publicKey: users[username].publicKey || null,
    privateKey: users[username].privateKey || null,
  });
});

app.get("/generate", (req, res) => {
  // Giả sử người dùng đã đăng nhập hoặc lấy username từ session
  const username = "demoUser"; // hoặc từ req.session.username
  res.render("generate", { username });
});


app.post("/generate", (req, res) => {
  const { username, keySize, purpose } = req.body;
  const size = parseInt(keySize) || 1024;
  const { publicKey, privateKey } = forge.pki.rsa.generateKeyPair(size);

  const publicPem = forge.pki.publicKeyToPem(publicKey);
  const privatePem = forge.pki.privateKeyToPem(privateKey);
  const safePurpose = purpose.replace(/\s+/g, "_");

  const keyDir = path.join(__dirname, "keys", username, safePurpose);
  if (!fs.existsSync(keyDir)) fs.mkdirSync(keyDir, { recursive: true });

  fs.writeFileSync(path.join(keyDir, "public_key.pem"), publicPem);
  fs.writeFileSync(path.join(keyDir, "private_key.pem"), privatePem);
  fs.writeFileSync(path.join(keyDir, "meta.json"), JSON.stringify({
    purpose,
    createdAt: new Date().toISOString()
  }, null, 2));

  res.redirect(`/keys/${username}`);
});



app.get("/keys/:username", (req, res) => {
  const username = req.params.username;
  const userDir = path.join(__dirname, "keys", username);

  if (!fs.existsSync(userDir)) {
    return res.send("Người dùng chưa tạo khóa nào.");
  }

  const purposes = fs.readdirSync(userDir, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);

  const keys = [];

  purposes.forEach(purposeFolder => {
    const metaPath = path.join(userDir, purposeFolder, "meta.json");

    if (fs.existsSync(metaPath)) {
      const meta = JSON.parse(fs.readFileSync(metaPath));
      keys.push({
        purpose: purposeFolder.replace(/_/g, " "),  // Dạng đẹp để hiển thị
        safePurpose: purposeFolder,                 // Dạng folder thực để dùng trong URL
        createdAt: meta.createdAt,
      });
    }
  });

  res.render("keys", { username, keys });
});



app.get("/download/public/:username/:purpose", (req, res) => {
  const { username, purpose } = req.params;
  const safePurpose = purpose.replace(/\s+/g, "_");
  const filePath = path.join(__dirname, "keys", username, safePurpose, "public_key.pem");

  if (!fs.existsSync(filePath)) return res.send("Chưa tạo khóa.");

  res.download(filePath);
});

app.get("/download/private/:username/:purpose", (req, res) => {
  const { username, purpose } = req.params;
  const safePurpose = purpose.replace(/\s+/g, "_");
  const filePath = path.join(__dirname, "keys", username, safePurpose, "private_key.pem");

  if (!fs.existsSync(filePath)) return res.send("Chưa tạo khóa.");

  res.download(filePath);
});

app.get("/view/:type/:username/:purpose", (req, res) => {
  const { type, username, purpose } = req.params;
  const safePurpose = purpose.replace(/\s+/g, "_");  // CHUYỂN đổi purpose thành safePurpose

  const filename = type === "public" ? "public_key.pem" : "private_key.pem";
  const filePath = path.join(__dirname, "keys", username, safePurpose, filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).send("Không tìm thấy khóa.");
  }

  res.setHeader("Content-Type", "text/plain");
  res.send(fs.readFileSync(filePath, "utf8"));
});

// Trang RSA tool
app.get("/rsa-tool/:username", (req, res) => {
  const username = req.params.username;
  res.render("rsa-tool", { username, result: null, error: null });
});

app.post("/rsa-tool/:username", upload.single("keyFile"), (req, res) => {
  const username = req.params.username;
  const { action, message, keyType } = req.body;
  let keyPem = req.body.key;

  try {
    if (req.file) {
      keyPem = fs.readFileSync(req.file.path, "utf8");
      fs.unlinkSync(req.file.path); // Xoá file tạm
    }

    if (!keyPem) {
      return res.render("rsa-tool", { username, result: null, error: "Vui lòng nhập hoặc tải lên khóa RSA." });
    }

    if (action === "encrypt" && keyType === "public") {
      const publicKey = forge.pki.publicKeyFromPem(keyPem);
      const encrypted = publicKey.encrypt(message, 'RSA-OAEP');
      const encryptedBase64 = forge.util.encode64(encrypted);
      return res.render("rsa-tool", { username, result: encryptedBase64, error: null });

    } else if (action === "decrypt" && keyType === "private") {
      const privateKey = forge.pki.privateKeyFromPem(keyPem);
      const encryptedBytes = forge.util.decode64(message);
      const decrypted = privateKey.decrypt(encryptedBytes, 'RSA-OAEP');
      return res.render("rsa-tool", { username, result: decrypted, error: null });

    } else {
      return res.render("rsa-tool", {
        username,
        result: null,
        error: "Loại khóa không phù hợp với hành động. Mã hóa cần khóa công khai, giải mã cần khóa riêng."
      });
    }

  } catch (e) {
    return res.render("rsa-tool", { username, result: null, error: "Lỗi xử lý: " + e.message });
  }
});

app.get('/sign-verify/:username', (req, res) => {
  res.render('sign-verify', { username: req.params.username, error: null, result: null });
});


app.post('/sign-file/:username', upload.fields([{ name: 'dataFile' }, { name: 'privateKey' }]), (req, res) => {
  try {
    if (!req.files.dataFile || !req.files.privateKey) {
      return res.status(400).send('Thiếu file dữ liệu hoặc khóa riêng tư.');
    }

    const dataPath = req.files.dataFile[0].path;
    const keyPath = req.files.privateKey[0].path;

    const data = fs.readFileSync(dataPath);
    const privateKey = fs.readFileSync(keyPath, 'utf-8');

    const signer = crypto.createSign('RSA-SHA256');
    signer.update(data);
    const signature = signer.sign(privateKey);

    const sigPath = `uploads/signature-${Date.now()}.sig`;
    fs.writeFileSync(sigPath, signature);

    res.download(sigPath, 'signature.sig', (err) => {
      if (err) console.error('Lỗi khi gửi file:', err);
      fs.unlink(dataPath, () => {});
      fs.unlink(keyPath, () => {});
      fs.unlink(sigPath, () => {});
    });

  } catch (err) {
    console.error(err);
    res.status(500).send('Lỗi xử lý ký file.');
  }
});


app.post('/verify-file/:username', upload.fields([
  { name: 'dataFile' },
  { name: 'signatureFile' },
  { name: 'publicKey' }
]), (req, res) => {
  const data = fs.readFileSync(req.files.dataFile[0].path);
  const signature = fs.readFileSync(req.files.signatureFile[0].path);
  const publicKey = fs.readFileSync(req.files.publicKey[0].path, 'utf-8');

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(data);
  const isValid = verifier.verify(publicKey, signature);

  fs.rmSync(req.files.dataFile[0].path);
  fs.rmSync(req.files.signatureFile[0].path);
  fs.rmSync(req.files.publicKey[0].path);

  if (isValid) {
    res.send('✅ File hợp lệ: không bị chỉnh sửa và đúng nguồn gốc.');
  } else {
    res.send('❌ File bị thay đổi hoặc không đúng chữ ký.');
  }
});

app.get('/dashboard/:username', (req, res) => {
  const username = req.params.username;

  // Ví dụ bạn lấy publicKey và privateKey từ đâu đó (database, file...)
  // Nếu chưa có, hãy truyền ít nhất null để tránh lỗi
  const publicKey = null;
  const privateKey = null;

  res.render('dashboard', {
    username,
    publicKey,
    privateKey
  });
});


app.listen(3000, () => {
  console.log("Chạy tại http://localhost:3000");
});
