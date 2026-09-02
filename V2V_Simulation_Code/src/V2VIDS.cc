//
// V2VIDS.cc
// Anomaly-based Intrusion Detection System module for V2V communication.
//
// Detects two attack vectors:
//   - Replay attacks: via duplicate (senderAddress, serial) detection.
//   - Phantom vehicle attacks: via a composite anomaly score derived from
//     inter-message interval regularity, serial-number continuity, and
//     message frequency.
//
// Per-message detection latency is measured as wall-clock processing time on
// the host, from message reception to the completed detection decision, using
// a high-resolution monotonic clock.
//
//
//
// MSc Cyber Security Research Paper (UFCE4B-60-M), UWE Bristol.
//

#include "veins/modules/application/traci/V2VIDS.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
#include <chrono>
#include <cmath>

using namespace veins;

Define_Module(veins::V2VIDS);

void V2VIDS::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);

    if (stage == 0) {
        windowSize         = par("windowSize").intValue();
        detectionThreshold = par("detectionThreshold").doubleValue();
        expectedInterval   = par("expectedInterval").doubleValue();
        intervalTolerance  = par("intervalTolerance").doubleValue();
        replayMode         = par("replayMode").boolValue();

        truePositives = falsePositives = trueNegatives = falseNegatives = 0;
        totalDetections = 0;
        mySerial = 0;

        detectionLatencySignal = registerSignal("detectionLatency");

        // Broadcast own BSMs at 10 Hz so neighbours and the replay attacker
        // have legitimate traffic to observe.
        bsmTimer = new cMessage("bsmTimer");
        scheduleAt(simTime() + 0.1, bsmTimer);
    }
}

bool V2VIDS::isPhantomSender(long senderAddress)
{
    // Phantom attacker uses an offset identifier (parent id + 9000).
    return (senderAddress >= 9000);
}

double V2VIDS::computeAnomalyScore(const SenderRecord& record,
                                   simtime_t currentTime,
                                   int currentSerial)
{
    if (record.timestamps.size() < 2) return 0.0;

    double score = 0.0;
    int checks = 0;

    // Check 1: inter-message interval deviation from the expected 0.1 s.
    simtime_t lastTime = record.timestamps.back();
    double interval = (currentTime - lastTime).dbl();
    double deviation = std::abs(interval - expectedInterval);
    if (deviation > intervalTolerance) {
        score += deviation / expectedInterval;
        checks++;
    }

    // Check 2: serial-number continuity (a genuine sender increments by one).
    if (!record.serials.empty()) {
        int lastSerial = record.serials.back();
        if (currentSerial != lastSerial + 1) {
            score += 1.0;
            checks++;
        }
    }

    // Check 3: message frequency over the last second.
    int recentCount = 0;
    simtime_t oneSecAgo = currentTime - 1.0;
    for (const auto& t : record.timestamps) {
        if (t > oneSecAgo) recentCount++;
    }
    if (recentCount > 12) {
        score += (recentCount - 10) / 10.0;
        checks++;
    }

    return checks > 0 ? score / checks : 0.0;
}

void V2VIDS::onWSM(BaseFrame1609_4* frame)
{
    // Start of per-message processing (wall-clock, high-resolution).
    auto _procStart = std::chrono::high_resolution_clock::now();

    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);
    long senderAddr = wsm->getSenderAddress();
    int serial      = wsm->getSerial();
    simtime_t recvTime = simTime();

    // Replay detection: duplicate (sender, serial) pair = replayed message.
    auto key = std::make_pair(senderAddr, serial);
    bool isReplay = (seenSerials.count(key) > 0);
    seenSerials.insert(key);

    bool isActualAttack = replayMode ? isReplay : isPhantomSender(senderAddr);

    SenderRecord& record = senderHistory[senderAddr];
    record.totalMessages++;

    double anomalyScore = computeAnomalyScore(record, recvTime, serial);

    record.timestamps.push_back(recvTime);
    record.serials.push_back(serial);
    if ((int)record.timestamps.size() > windowSize) {
        record.timestamps.pop_front();
        record.serials.pop_front();
    }

    // For replay: flag duplicates directly.
    bool detected = replayMode ? isReplay : (anomalyScore >= detectionThreshold);

    // Per-message processing latency (wall-clock, on the simulation host),
    // captured from entry to the completed detection decision.
    auto _procEnd = std::chrono::high_resolution_clock::now();
    double _procNs = std::chrono::duration<double, std::nano>(_procEnd - _procStart).count();
    emit(detectionLatencySignal, _procNs);

    if (blacklistedSenders.count(senderAddr) && !replayMode) {
        if (isActualAttack) truePositives++;
        else falsePositives++;
        return;
    }

    if (detected) {
        if (!replayMode) blacklistedSenders.insert(senderAddr);
        record.anomalyCount++;
        totalDetections++;

        EV_INFO << "IDS ALERT on " << getParentModule()->getFullName()
                << " | sender=" << senderAddr
                << " replay=" << isReplay
                << " score=" << anomalyScore
                << " t=" << recvTime << endl;

        if (isActualAttack) truePositives++;
        else falsePositives++;
    } else {
        if (isActualAttack) falseNegatives++;
        else trueNegatives++;
    }
}

void V2VIDS::handleSelfMsg(cMessage* msg)
{
    if (msg == bsmTimer) {
        TraCIDemo11pMessage* bsm = new TraCIDemo11pMessage();
        populateWSM(bsm);
        bsm->setSenderAddress(myId);
        bsm->setSerial(mySerial++);
        bsm->setDemoData("");
        sendDown(bsm);
        scheduleAt(simTime() + 0.1, bsmTimer);
    } else {
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void V2VIDS::onWSA(DemoServiceAdvertisment* wsa) {}

void V2VIDS::finish()
{
    double tpr = (truePositives + falseNegatives) > 0 ?
        (double)truePositives / (truePositives + falseNegatives) : 0.0;
    double fpr = (falsePositives + trueNegatives) > 0 ?
        (double)falsePositives / (falsePositives + trueNegatives) : 0.0;
    double precision = (truePositives + falsePositives) > 0 ?
        (double)truePositives / (truePositives + falsePositives) : 0.0;
    double f1 = (precision + tpr) > 0 ? 2 * precision * tpr / (precision + tpr) : 0.0;

    recordScalar("truePositives",  truePositives);
    recordScalar("falsePositives", falsePositives);
    recordScalar("trueNegatives",  trueNegatives);
    recordScalar("falseNegatives", falseNegatives);
    recordScalar("TPR", tpr);
    recordScalar("FPR", fpr);
    recordScalar("precision", precision);
    recordScalar("F1", f1);
    recordScalar("totalDetections", totalDetections);

    cancelAndDelete(bsmTimer);
    DemoBaseApplLayer::finish();
}
