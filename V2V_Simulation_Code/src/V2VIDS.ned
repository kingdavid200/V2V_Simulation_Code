//
// V2VIDS.ned
// NED declaration for the anomaly-based IDS application module.
//

package org.car2x.veins.modules.application.traci;

import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple V2VIDS extends DemoBaseApplLayer
{
    parameters:
        @class(veins::V2VIDS);

        int windowSize = default(10);
        double detectionThreshold = default(0.5);
        double expectedInterval = default(0.1);      // s (10 Hz BSM rate)
        double intervalTolerance = default(0.05);    // s
        bool replayMode = default(false);

        @signal[detectionLatency](type=double);
        @statistic[detectionLatency](title="Detection Latency (ns)"; source=detectionLatency; record=vector,mean,max,min);
}
