//
// PhantomVehicleAttacker.cc
// Broadcasts fabricated BSMs reporting a non-existent (phantom) stationary
// vehicle at a fixed position, at 10 Hz from a configurable start time.
// Uses an offset source identifier (parent id + 9000) and signs with its own
// valid certificate, so fabricated messages pass signature verification.
//

#include "veins/modules/application/traci/PhantomVehicleAttacker.h"
#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"

using namespace veins;

Define_Module(veins::PhantomVehicleAttacker);

void PhantomVehicleAttacker::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        phantomX          = par("phantomX").doubleValue();
        phantomY          = par("phantomY").doubleValue();
        phantomSpeed      = par("phantomSpeed").doubleValue();
        phantomHeading    = par("phantomHeading").doubleValue();
        attackStartTime   = par("attackStartTime").doubleValue();
        totalPhantomBSMsSent = 0;

        attackTimer = new cMessage("attackTimer");
        scheduleAt(simTime() + attackStartTime, attackTimer);
    }
}

void PhantomVehicleAttacker::handleSelfMsg(cMessage* msg)
{
    if (msg == attackTimer) {
        sendPhantomBSM();
        scheduleAt(simTime() + 0.1, attackTimer);   // 10 Hz
    } else {
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void PhantomVehicleAttacker::sendPhantomBSM()
{
    TraCIDemo11pMessage* phantom = new TraCIDemo11pMessage();
    populateWSM(phantom);

    // Fabricated source identity (offset from legitimate id space).
    phantom->setSenderAddress(getParentModule()->getId() + 9000);

    // Broadcast the fabricated kinematic state (a phantom stationary obstacle).
    phantom->setSenderPosition(Coord(phantomX, phantomY));
    phantom->setSenderSpeed(phantomSpeed);
    phantom->setSenderHeading(phantomHeading);
    phantom->setDemoData("");

    sendDown(phantom);
    totalPhantomBSMsSent++;

    EV_INFO << "Phantom BSM #" << totalPhantomBSMsSent
            << " sent at t=" << simTime()
            << " claiming position (" << phantomX << ", " << phantomY << ")" << endl;
}

void PhantomVehicleAttacker::finish()
{
    recordScalar("totalPhantomBSMsSent", totalPhantomBSMsSent);
    cancelAndDelete(attackTimer);
    DemoBaseApplLayer::finish();
}
