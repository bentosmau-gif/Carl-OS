#include "signature.h"
#include <iostream>

SignatureDatabase::SignatureDatabase() {
    std::cout << "[SignatureDatabase] Initialized\n";
    loadSignatures();
}

SignatureDatabase::~SignatureDatabase() {
}

void SignatureDatabase::addSignature(const std::string& name, const std::string& pattern, int severity) {
    signatures.push_back({name, "", pattern, severity});
}

void SignatureDatabase::loadSignatures() {
    // Common malware patterns - more specific to reduce false positives
    addSignature("Trojan.Psimplesteal", "psimplesteal", 10);
    addSignature("Worm.Conficker", "conficker", 10);
    addSignature("Ransom.WannaCry", "wcry", 10);
    addSignature("Backdoor.Shell", "shell_execute_remote", 9);
    addSignature("Spyware.Keylogger", "hook_keyboard_input", 9);
    addSignature("Exploit.CVE", "CVE-", 8);
    addSignature("Crypto.Miner", "stratum", 7);
    addSignature("Trojan.Dropper", "payload_inject", 9);
    
    std::cout << "[SignatureDatabase] Loaded " << signatures.size() << " signatures\n";
}

bool SignatureDatabase::matchesSignature(const std::string& content, const std::string& filePath) {
    for (const auto& sig : signatures) {
        if (content.find(sig.pattern) != std::string::npos) {
            lastMatchedSignature = sig.name;
            return true;
        }
    }
    return false;
}

std::string SignatureDatabase::getMatchedSignatureName() {
    return lastMatchedSignature;
}
