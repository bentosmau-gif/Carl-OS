#ifndef ANTIVIRUS_H
#define ANTIVIRUS_H

#include <string>
#include <vector>
#include "scanner.h"
#include "heuristic.h"
#include "signature.h"

class AntiVirus {
public:
    AntiVirus();
    ~AntiVirus();
    
    void initialize();
    void scanTarget(const std::string& targetPath);
    void printResults();
    
private:
    Scanner scanner;
    HeuristicAnalyzer heuristic;
    SignatureDatabase signatures;
    std::vector<ScanResult> results;
    
    void performFullAnalysis(ScanResult& result);
    void printScanResult(const ScanResult& result);
};

#endif

// [C] Bentosmau-gif - Dev 26/ all rights reserved.
