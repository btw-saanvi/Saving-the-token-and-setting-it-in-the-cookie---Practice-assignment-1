const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const SECRET_KEY = "your_jwt_secret"; // Change this to a strong secret
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32-byte key for AES encryption
const IV = crypto.randomBytes(16); // 16-byte IV for AES encryption

const encrypt = (payload) => {
  // Generate a JWT token
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });

  // Encrypt the JWT token
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, "utf8", "hex");
  encrypted += cipher.final("hex");

  return { encryptedToken: encrypted, iv: IV.toString("hex") };
};

const decrypt = ({ encryptedToken, iv }) => {
  // Decrypt the JWT token
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    ENCRYPTION_KEY,
    Buffer.from(iv, "hex")
  );
  let decrypted = decipher.update(encryptedToken, "hex", "utf8");
  decrypted += decipher.final("utf8");

  // Verify and decode JWT
  return jwt.verify(decrypted, SECRET_KEY);
};

module.exports = {
  encrypt,
  decrypt,
};
