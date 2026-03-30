# Test Cases

## 1. Peer Discovery
- Start Go and Python clients
- Expected: automatic discovery and connection

## 2. File Listing
- Command: list <peer>
- Expected: list of available files

## 3. File Transfer
- Command: get <peer> <file>
- Expected: file received and verified

## 4. File Integrity Failure
- Modify file during transfer (or simulate wrong hash)
- Expected: "file integrity check FAILED"

## 5. Consent Test
- Reject file request
- Expected: transfer does not occur

## 6. Disconnection Handling
- Stop one peer
- Expected: error message or disconnect log

## 7. Multi-peer Transfer
- Download file from different peer
- Expected: file still verifies correctly