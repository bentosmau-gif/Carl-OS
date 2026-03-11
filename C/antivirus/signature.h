#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <string>
#include <vector>
#include <map>

struct MalwareSignature {
    std::string name;
    std::string hash;
    std::string pattern;
    int severity; // 0-10
};

class SignatureDatabase {
public:
    SignatureDatabase();
    ~SignatureDatabase();
    
    void loadSignatures();
    bool matchesSignature(const std::string& content, const std::string& filePath);
    std::string getMatchedSignatureName();
    
private:
    std::vector<MalwareSignature> signatures;
    std::string lastMatchedSignature;
    
    void addSignature(const std::string& name, const std::string& pattern, int severity);
};

#endif

// [C] bentosmau-gif - Dev 26/ All rights reserved
