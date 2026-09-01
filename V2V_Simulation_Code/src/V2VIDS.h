//
// V2VIDS.h
// Anomaly-based Intrusion Detection System module for V2V communication.
//
// Detects two attack vectors:
//   - Replay attacks: via duplicate (senderAddress, serial) detection.
//   - Phantom vehicle attacks: via a composite anomaly score derived from
//     inter-message interval regularity, serial-number continuity, and
//     message frequency.
//
// NOTE: This file was reconstructed from development-session records. It is
// functionally faithful to the implementation that produced the reported
// results but should be reconciled against the authoritative copy on the
// simulation VM before archival submission.
//
// MSc Cyber Security Research Paper (UFCE4B-60-M), UWE Bristol.
//

#pragma once

#include <map>
#include <set>
#include <deque>
#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"

namespace veins {

// Per-sender record: sliding windows of recent timestamps and serials.
struct SenderRecord {
    std::deque<simtime_t> timestamps;
    std::deque<int> serials;
    int anomalyCount = 0;
};

class VEINS_API V2VIDS : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;
    void finish() override;

protected:
    // Sliding window length (messages retained per sender).
    int windowSize;

    // Composite-score detection threshold (a sender scoring >= this is flagged).
    double detectionThreshold;

    // Expected BSM interval (s) and tolerance for the interval check.
    double expectedInterval;
    double intervalTolerance;

    // When true, detection is by duplicate-serial replay check only.
    bool replayMode;

    // Per-sender history and replay bookkeeping.
    std::map<long, SenderRecord> senderHistory;
    std::set<long> blacklistedSenders;
    std::set<std::pair<long, int>> seenSerials;

    // Confusion-matrix counters (aggregated at message level).
    int truePositives;
    int falsePositives;
    int trueNegatives;
    int falseNegatives;
    int totalDetections;

    // Latency signal (records detection time; see note in Discussion/limitations).
    simsignal_t detectionLatencySignal;

    // Own-BSM broadcast timer and serial counter.
    cMessage* bsmTimer;
    int mySerial;

protected:
    void onWSM(BaseFrame1609_4* wsm) override;
    void onWSA(DemoServiceAdvertisment* wsa) override;
    void handleSelfMsg(cMessage* msg) override;

    // Ground-truth helper: phantom sources use an offset identifier space.
    bool isPhantomSender(long senderAddress);

    // Composite anomaly score for phantom detection.
    double computeAnomalyScore(const SenderRecord& record,
                               simtime_t currentTime,
                               int currentSerial);
};

} // namespace veins
