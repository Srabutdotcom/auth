After receiving the **Finished** message in TLS 1.3, you need to verify it and transition to the **Application Data** phase if verification succeeds. Here’s what you should do:

### **1. Compute Expected Finished Message**
   - The **Finished** message contains an HMAC over the handshake transcript.
   - Compute the transcript hash of all previous handshake messages.
   - Use the **finished_key** (derived from the handshake secret) to generate the expected **Finished** message.

### **2. Verify the Finished Message**
   - Compare the received **Finished** message with the expected value.
   - If they match, authentication is complete.

### **3. Switch to Application Data Phase**
   - If the **Finished** message is valid:
     - Derive the **application traffic secrets**.
     - Start encrypting and decrypting application data using these secrets.
   - If verification fails, **terminate the connection**.

---

### **Code Example for Verifying Finished Message**
```javascript

const expectedFinished = await finished(finishedKey, sha = 256, handshakeMessages) 
if(finished, expectedFinished)return true
return false
```
---

### **Final Steps**
✅ If verification succeeds:  
   - Switch to **Application Data phase**  
   - Use **derived keys** for secure communication  

❌ If verification fails:  
   - **Terminate the connection** (possible MITM attack)