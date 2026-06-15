const express = require('express');
const axios = require('axios');
const pdf = require('pdf-parse');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const https = require('https');
require('dotenv').config();
const app = express();
// Set up security headers
app.use(helmet());
// Enable CORS with secure configurations (allow customizing origins if needed)
app.use(cors({
    origin: '*', // Set to specific domains in production
    methods: ['GET', 'POST']
}));
// Parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
// Rate Limiter to prevent brute-forcing TXIDs (DoS protection)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 60, // Limit each IP to 60 requests per window
    message: 'Too many requests from this IP, please try again after 15 minutes.',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/verify-payment', limiter);
// Create an HTTPS agent that ignores unauthorized certs if needed (CBE portal often uses custom SSL)
const httpsAgent = new https.Agent({
    rejectUnauthorized: false
});
// 1. Root Route
const rootHandler = (req, res) => {
    res.send('BirrPay Secure Backend Service is Running Successfully!');
};
app.get('/', rootHandler);
app.get('/verify-payment', rootHandler);
// 2. Payment Verification Route
const verifyHandler = async (req, res) => {
    const { txid, amount } = req.body;
    
    // Validation: Check for missing inputs
    if (!txid || !amount) {
        console.warn(`[Verification Rejected] Missing parameters. Amount: ${amount}, TXID: ${txid}`);
        return res.status(400).send('Rejected: Missing parameters');
    }
    
    // SSRF & Injection Protection: Validate that transaction ID contains only alphanumeric characters
    const txidRegex = /^[A-Za-z0-9_\-]+$/;
    if (!txidRegex.test(txid)) {
        console.warn(`[Verification Rejected] Invalid TXID character format: "${txid}"`);
        return res.send('Rejected');
    }
    
    // Validate that amount is numeric and positive
    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
        console.warn(`[Verification Rejected] Invalid target amount: "${amount}"`);
        return res.send('Rejected');
    }
    
    const static_acc = process.env.CBE_ACCOUNT || "79288799";
    const baseUrl = process.env.CBE_RECEIPT_BASE_URL || "https://apps.cbe.com.et:100/BranchReceipt";
    
    // Build request URL securely
    const link = `${baseUrl}/${encodeURIComponent(txid)}&${encodeURIComponent(static_acc)}`;
    
    try {
        console.log(`[Verifying] TXID: ${txid} | Expected Amount: ${parsedAmount} | URL: ${link}`);
        
        // Fetch receipt document from CBE Portal with browser-like headers to bypass blocks
        const response = await axios.get(link, { 
            responseType: 'arraybuffer',
            timeout: 10000, // 10 seconds timeout
            httpsAgent: httpsAgent,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            }
        });
        
        // Parse PDF content
        const data = await pdf(response.data);
        const pdfText = data.text;
        
        // Write the parsed PDF text to a local file for debugging (using txid to avoid concurrency conflicts)
        const fs = require('fs');
        try {
            fs.writeFileSync(`parsed_receipt_${txid}.txt`, pdfText);
            console.log(`[Debug Log] Parsed text written to parsed_receipt_${txid}.txt`);
        } catch (fsErr) {
            console.error(`[Debug Log Error] Failed to write parsed_receipt_${txid}.txt: ${fsErr.message}`);
        }
        
        // Regex to identify the debited amount (CBE receipts contain "Total amount debited...")
        // Updated to handle multiline whitespace ([\s]*) and alternative descriptors
        const amountRegex = /(?:Total amount debited from customers account|Amount|Transaction Amount|Debit Amount|Transfer Amount|Total Debited|Debited Amount)[\s]*[:.]?[\s]*(?:ETB|USD|Birr)?[\s]*([\d,.]+)/i;
        const match = pdfText.match(amountRegex);
        
        if (match) {
            const fileAmount = parseFloat(match[1].replace(/,/g, ''));
            console.log(`[Info] Found amount in receipt: ${fileAmount} ETB`);
            
            // Strict match: Ensure the paid amount matches the invoice amount exactly (within 2 Birr tolerance)
            if (Math.abs(fileAmount - parsedAmount) <= 2.0) {
                console.log(`[Approved] Verification Successful for TXID: ${txid}`);
                return res.send('Approved');
            } else {
                console.warn(`[Rejected] Amount mismatch. Got ${fileAmount} ETB, expected ${parsedAmount} ETB`);
            }
        } else {
            console.warn(`[Rejected] Could not locate debit amount in receipt PDF structure.`);
        }
        res.send('Rejected');
    } catch (error) {
        console.error(`[Verification Error] Error fetching or parsing CBE receipt: ${error.message}`);
        // Default safe rejection on connection/server failures
        res.send('Rejected');
    }
};
app.post('/', verifyHandler);
app.post('/verify-payment', verifyHandler);
// 3. Server Startup
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`BirrPay service is live and running on port ${port}`);
});
