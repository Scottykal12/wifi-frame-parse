use libwifi::{
    self,
    frame::{components::MacAddress, *},
    Addresses,
};
use pcap::{Capture, Device};
use radiotap::Radiotap;
use std::{collections::HashMap, env, process::Command};

fn main() {
    let args: Vec<String> = env::args().collect();

    let command = &args[1];
    let int = &args[2];

    if command == "--scan" || command == "-s" {
        scan(int);
    }

    if command == "--monitor" || command == "-m" {
        mon_mode(int);
    }

    if command == "--managed" || command == "-g" {
        man_mode(int);
    }
}

// nmcli device set wlp0s20f3 managed no

fn mon_mode(interface: &String) {
    // nmcli device set wlp0s20f3 managed no
    // sudo ip link set wlp1s0 down
    // sudo iw wlp1s0 set monitor none
    // sudo ip link set wlp1s0 up

    // issue with this not staying up. The interface keeps getting grabed by netdev / netmanger
    // airmon just adds a new interface to steal it from netmanager
    // imma try nmcli managed no

    let _nmcli = Command::new("nmcli")
        .arg("device")
        .arg("set")
        .arg("wlp0s20f3")
        .arg("managed")
        .arg("no")
        .output()
        .expect("failed to execute process");

    let _linkdown = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg(interface)
        .arg("down")
        .output()
        .expect("failed to bring interface down");

    let _monmode = Command::new("sudo")
        .arg("iw")
        .arg("dev")
        .arg(interface)
        .arg("set")
        .arg("type")
        .arg("monitor")
        .output()
        .expect("failed to enable monitor mode on interface");

    let _linkup = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg(interface)
        .arg("up")
        .output()
        .expect("failed to bring interface up");
}

fn man_mode(interface: &String) {
    // sudo ip link set wlp1s0 down
    // sudo iw wlp1s0 set type managed
    // sudo ip link set wlp1s0 up
    // nmcli device set wlp0s20f3 managed no

    let _linkdown = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg(interface)
        .arg("down")
        .output()
        .expect("failed to bring interface down");

    let _monmode = Command::new("sudo")
        .arg("iw")
        .arg(interface)
        .arg("set")
        .arg("type")
        .arg("managed")
        .output()
        .expect("failed to enable monitor mode on interface");

    let _linkup = Command::new("sudo")
        .arg("ip")
        .arg("link")
        .arg("set")
        .arg(interface)
        .arg("up")
        .output()
        .expect("failed to bring interface up");

    let _nmcli = Command::new("nmcli")
        .arg("device")
        .arg("set")
        .arg("wlp0s20f3")
        .arg("managed")
        .arg("yes")
        .output()
        .expect("failed to execute process");
}

fn scan(interface: &str) {
    // TODO: set device manually

    let dev: Device = pcap::Device::from(interface);
    // .expect("device lookup failed")
    // .expect("no device available");

    loop {
        let mut cap = Capture::from_device(dev.clone())
            .unwrap()
            .promisc(true) //Promiscous mode
            .timeout(100) //1 sec timeout
            .snaplen(240)
            .open()
            .unwrap();

        if let Ok(pkt) = cap.next_packet() {
            // GET RADIOTAP INFO
            let rdtap = Radiotap::from_bytes(&pkt.data).unwrap();

            // PARSE 802.11 FRAMES
            if let Ok(frm) = libwifi::parse_frame(&pkt.data[rdtap.header.length..]) {
                match frm {
                    libwifi::Frame::Beacon(beacon) => parse_beacon(beacon),
                    // libwifi::Frame::ProbeRequest(proberequest) => parse_proberequest(proberequest),
                    // libwifi::Frame::ProbeResponse(proberesponse) => parse_proberesponse(proberesponse),
                    // libwifi::Frame::AssociationRequest(associationrequest) => parse_assosiationrequest(associationrequest),
                    // libwifi::Frame::AssociationResponse(associationresposnse) => parse_assosiationresponse(associationresposnse),
                    // libwifi::Frame::Rts(rts) => parse_RTS(rts),
                    // libwifi::Frame::Cts(cts) => parse_CTS(cts),
                    // libwifi::Frame::Ack(ack) => parse_ACK(ack),
                    // libwifi::Frame::BlockAckRequest(blockackrequest) => parse_blockackrequest(blockackrequest),
                    // libwifi::Frame::BlockAck(blockack) => parse_blockack(blockack),
                    libwifi::Frame::Data(data) => parse_data(data),
                    // libwifi::Frame::NullData(nulldata) => parse_nulldata(nulldata),
                    // libwifi::Frame::QosData(qosdata) => parse_qosdata(qosdata),
                    // libwifi::Frame::QosNull(qosnull) => parse_qosnull(qosnull),
                    _ => (),
                }
            }
        }
    }
}

fn convert_mac_hex(macadd: &MacAddress) -> String {
    let mut mac = String::from("");
    for i in macadd.0 {
        let oct = format!("{:02X}", i);
        mac.extend([oct]);
    }
    return mac;
}

// TODO: add the corect output for each function. ie beacon pushes beacon...
fn parse_beacon(beacon: Beacon) {
    println!("Beacon");
    println!("   |{:?}", beacon.station_info.ssid.as_ref().unwrap());
    println!("   |{:?}", convert_mac_hex(beacon.bssid().as_ref().unwrap()));
}

// fn parse_proberequest(proberequest: ProbeRequest) {
//     println!("Probe Request");
// }

// fn parse_proberesponse(proberesponse: ProbeResponse) {
//     println!("Probe Response");
// }

// fn parse_assosiationrequest(associationrequest: AssociationRequest) {
//     println!(" Association Request");
// }

// fn parse_assosiationresponse(associationresponse: AssociationResponse) {
//     println!("Association Response");
// }

// fn parse_RTS(rts: Rts) {
//     println!("RTS");
// }

// fn parse_CTS(cts: Cts) {
//     println!("CTS");
// }

// fn parse_ACK(ack: Ack) {
//     println!("ACK");
// }

// fn parse_blockackrequest(blockackrequest: BlockAckRequest) {
//     println!("Block ACK Request");
// }

// fn parse_blockack(blockack: BlockAck) {
//     println!("Block ACK");
// }

fn parse_data(data: Data) {
    println!("Data");
    println!("{:?}", convert_mac_hex(&data.header.address_1));
    println!("{:?}", convert_mac_hex(&data.header.address_2));
    println!("{:?}", convert_mac_hex(&data.header.address_3));
}

// fn parse_nulldata(nulldata: NullData) {
//     println!("Null Data");
// }

// fn parse_qosdata(qosdata: QosData) {
//     println!("QOS Data");
// }

// fn parse_qosnull(qosnull: QosNull) {
//     println!("QOS Null");
// }
