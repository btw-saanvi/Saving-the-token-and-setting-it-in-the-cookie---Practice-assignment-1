require("dotenv").config();
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");

const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET;

// Function to generate a JWT token
function generateJWT(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

// Function to encrypt the JWT token
function encryptToken(token) {
    return CryptoJS.AES.encrypt(token, ENCRYPTION_SECRET).toString();
}

// Function to decrypt the JWT token
function decryptToken(encryptedToken) {
    const bytes = CryptoJS.AES.decrypt(encryptedToken, ENCRYPTION_SECRET);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// Function to verify and decode a JWT token
function verifyJWT(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return "Invalid Token!";
    }
}

// Testing the encryption and decryption
function testJWTEncryption() {
    const payload = { userId: 123, username: "testUser" };

    console.log("\n🔹 Generating JWT...");
    const token = generateJWT(payload);
    console.log("JWT Token:", token);

    console.log("\n🔹 Encrypting JWT...");
    const encryptedToken = encryptToken(token);
    console.log("Encrypted Token:", encryptedToken);

    console.log("\n🔹 Decrypting JWT...");
    const decryptedToken = decryptToken(encryptedToken);
    console.log("Decrypted Token:", decryptedToken);

    console.log("\n🔹 Verifying Decrypted JWT...");
    const decodedData = verifyJWT(decryptedToken);
    console.log("Decoded Data:", decodedData);

    if (decodedData.userId) {
        console.log("\n✅ Success: JWT encryption and decryption works correctly!");
    } else {
        console.log("\n❌ Error: Something went wrong!");
    }
}

// Run the test
testJWTEncryption();