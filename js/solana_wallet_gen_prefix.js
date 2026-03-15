// save as vanity-sol.js
// npm install @solana/web3.js bs58 tweetnacl
const { Keypair } = require('@solana/web3.js');
const bs58 = require('bs58');
const fs = require('fs');
const path = require('path');

const prefix = (process.argv[2] || 'PUMP'); // e.g. node vanity-sol.js PUMP
const max = parseInt(process.argv[3] || '0'); // 0 = infinite, or number of matches to find

// Create output file name based on prefix and timestamp
const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const outputFile = `wallets_${prefix}_${timestamp}.txt`;
const outputPath = path.join(__dirname, outputFile);
~
// Startup logging
console.log('🚀 Starting Solana vanity wallet generator');
console.log(`📋 Search parameters:`);
console.log(`   - Prefix: "${prefix}"`);
console.log(`   - Max wallets: ${max === 0 ? 'unlimited' : max}`);
console.log(`   - Output file: ${outputFile}`);
console.log('⏱️  Starting search...\n');

let found = 0;
let attempts = 0;
const startTime = Date.now();
console.time('search');

// Progress logging interval
const progressInterval = setInterval(() => {
  const elapsed = (Date.now() - startTime) / 1000;
  const rate = attempts / elapsed;
  const successRate = attempts > 0 ? (found / attempts * 100) : 0;
  console.log(`📊 Progress: ${attempts.toLocaleString()} attempts, ${found} found (${successRate.toFixed(4)}% success rate, ${rate.toFixed(0)} attempts/sec)`);
}, 5000); // Log progress every 5 seconds

// Async function to allow progress logging
async function searchWallets() {
  while (max === 0 || found < max) {
    // Process in batches to allow other operations
    for (let i = 0; i < 1000; i++) {
      attempts++;
      const kp = Keypair.generate();
      const pub = kp.publicKey.toBase58();
      if (pub.startsWith(prefix)) {
        found++;
        const secretKey = bs58.encode(kp.secretKey);
        
        // Log to console
        console.log(`\n✅ FOUND #${found}:`, pub);
        console.log('🔑 SECRET (base58):', secretKey);
        console.log(`📈 Found after ${attempts.toLocaleString()} attempts\n`);
        
        // Save to file
        const walletData = `Wallet #${found}\n` +
                          `Public Key:  ${pub}\n` +
                          `Private Key: ${secretKey}\n` +
                          `Found after: ${attempts.toLocaleString()} attempts\n` +
                          `Timestamp:   ${new Date().toISOString()}\n` +
                          `${'='.repeat(60)}\n\n`;
        
        fs.appendFileSync(outputPath, walletData);
        console.log(`💾 Wallet saved to ${outputFile}`);
        
        // optionally save to file or break if you only wanted 1
        // break;
      }
      
      // Break out of batch if we've found enough
      if (max > 0 && found >= max) break;
    }
    
    // Yield control to allow progress logging
    await new Promise(resolve => setImmediate(resolve));
  }
}

// Run the search
searchWallets().then(() => {
  clearInterval(progressInterval);
  console.timeEnd('search');

  // Final summary
  const totalTime = (Date.now() - startTime) / 1000;
  const finalRate = attempts / totalTime;
  const finalSuccessRate = found / attempts * 100;
  console.log('\n🎯 Search completed!');
  console.log(`📊 Final statistics:`);
  console.log(`   - Total attempts: ${attempts.toLocaleString()}`);
  console.log(`   - Wallets found: ${found}`);
  console.log(`   - Success rate: ${finalSuccessRate.toFixed(6)}%`);
  console.log(`   - Average rate: ${finalRate.toFixed(0)} attempts/second`);
  console.log(`   - Total time: ${totalTime.toFixed(2)} seconds`);
  
  if (found > 0) {
    console.log(`💾 All wallets saved to: ${outputFile}`);
  }
});