//
// ReplayAttacker.cc
// Passively captures legitimate BSMs and retransmits each after a random
// delay drawn from U(0.5, 2.0) s. Retransmissions are exact copies (via dup())
// carrying the original sender's valid signature and original serial, so they
// are indistinguishable from legitimate messages at the cryptographic layer.
//

#include "veins/modules/application/traci/ReplayAttacker.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"

using namespace veins;

Define_Module(veins::ReplayAttacker);

void ReplayAttacker::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        totalReplayed = 0;
        replayTimer = new cMessage("replayTimer");
    }
}

void ReplayAttacker::onWSM(BaseFrame1609_4* frame)
{
    // Capture a copy of every legitimate BSM observed on the channel.
    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);
    TraCIDemo11pMessage* copy = wsm->dup();

    // Schedule retransmission after a random delay in [0.5, 2.0] s.
    double delay = uniform(0.5, 2.0);
    ReplayEntry entry;
    entry.msg = copy;
    entry.replayAt = simTime() + delay;
    replayQueue.push_back(entry);

    // Ensure the timer is armed for the earliest pending replay.
    if (!replayTimer->isScheduled()) {
        scheduleAt(replayQueue.front().replayAt, replayTimer);
    }
}

void ReplayAttacker::handleSelfMsg(cMessage* msg)
{
    if (msg == replayTimer) {
        simtime_t now = simTime();
        while (!replayQueue.empty() && replayQueue.front().replayAt <= now) {
            TraCIDemo11pMessage* replay = replayQueue.front().msg;
            replayQueue.pop_front();
            sendDown(replay);
            totalReplayed++;
        }
        if (!replayQueue.empty()) {
            scheduleAt(replayQueue.front().replayAt, replayTimer);
        }
    } else {
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void ReplayAttacker::finish()
{
    recordScalar("totalReplayed", totalReplayed);
    while (!replayQueue.empty()) {
        delete replayQueue.front().msg;
        replayQueue.pop_front();
    }
    cancelAndDelete(replayTimer);
    DemoBaseApplLayer::finish();
}
