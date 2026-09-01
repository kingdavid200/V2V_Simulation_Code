//
// TraCIDemo11pMessage.msg
// BSM message definition, extended with kinematic fields (position, speed,
// heading) so that senders can carry claimed kinematic state and receivers
// (the IDS) can assess it. Base Veins message extended for this study.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

import veins.base.utils.Coord;
import veins.modules.messages.BaseFrame1609_4;
import veins.base.utils.SimpleAddress;

namespace veins;

packet TraCIDemo11pMessage extends BaseFrame1609_4 {
    string demoData;
    LAddress::L2Type senderAddress = -1;
    int serial = 0;
    Coord senderPosition;
    double senderSpeed = 0;
    double senderHeading = 0;
}
