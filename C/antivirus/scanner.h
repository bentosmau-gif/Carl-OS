// [C] Bentosmau-gif - Dev 26/ all rights reserved.
#include SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>

enum class ThreatLevel {
    CLEAN = 0,
    SUSPICIOUS = 1,
    MALWARE = 2
};

struct ScanResult {
    std::string filePath;
    ThreatLevel threatLevel;
    std::string detectionName;
    std::string details;
};

class Scanner {
public:
    Scanner();
    ~Scanner();
    
    ScanResult scanFile(const std::string& filePath);
    std::vector<ScanResult> scanDirectory(const std::string& dirPath);
    
private:
    bool fileExists(const std::string& filePath);
    std::string readFileContent(const std::string& filePath);
};

#endif
