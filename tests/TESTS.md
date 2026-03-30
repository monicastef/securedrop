# Test Cases

## 1. Peer Discovery
Start Go and Python clients  
Expected: automatic discovery and connection

## 2. File Listing
Command: list <peer>  
Expected: list of available files

## 3. File Transfer
Command: get <peer> <file>  
Expected: file downloaded and verified

## 4. Integrity Verification
Modify file before sending  
Expected: "integrity check FAILED"

## 5. Signature Verification
Tamper with signature  
Expected: "signature verification FAILED"

## 6. Authentication
Change peer identity (restart with new keys)  
Expected: "identity mismatch"

## 7. Key Rotation
Run: rotate-key  
Reconnect  
Expected: mismatch warning

## 8. Disconnection Handling
Stop a peer  
Expected: disconnect message

## 9. Multi-peer Transfer
Download file from another peer  
Expected: verification still succeeds