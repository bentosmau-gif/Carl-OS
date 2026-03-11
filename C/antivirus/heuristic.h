#ifndef HEURISTIC_H
#define HEURISTIC_H

#include <string>
#include <vector>
#include "scanner.h"

class HeuristicAnalyzer {
public:
    HeuristicAnalyzer();
    ~HeuristicAnalyzer();
    
    ThreatLevel analyzeBehavior(const std::string& content);
    std::string generateRiskReport(const std::vector<ScanResult>& results);
    
private:
    int calculateRiskScore(const std::string& content);
    bool hasNetworkBehavior(const std::string& content);
    bool hasFileSystemBehavior(const std::string& content);
    bool hasRegistryBehavior(const std::string& content);
    bool hasEncryptionBehavior(const std::string& content);
};

#endif

// [C] bentosmau-gif - Dev 26/ all rights reserved
