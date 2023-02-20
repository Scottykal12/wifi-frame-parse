use libwifi::{
    self,
    frame::{components::MacAddress, Beacon, ProbeRequest, ProbeResponse, AssociationRequest, AssociationResponse, Rts, Cts, Ack, BlockAckRequest, BlockAck, Data, NullData, QosData, QosNull},
    Frame,
};
use pcap::{Capture, Device};
use radiotap::Radiotap;

fn main() {
    // println!("{:?}", Device::list());
    // TODO: set device manually

    let dev: Device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");

    loop {
        let mut cap = Capture::from_device(dev.clone())
            .unwrap()
            .promisc(true) //Promiscous mode
            .timeout(1) //1 sec timeout
            .open()
            .unwrap();

        if let Ok(pkt) = cap.next_packet() {
            // GET RADIOTAP INFO
            let rdtap = Radiotap::from_bytes(&pkt.data).unwrap();

            // PARSE 802.11 FRAMES
            if let Ok(frm) = libwifi::parse_frame(&pkt.data[rdtap.header.length..]) {
                // println!("{:?}", frm);
                match frm {
                    // can this be done without spelling it out? don't need every line
                    libwifi::Frame::Beacon(beacon) => parse_beacon(beacon),
                    libwifi::Frame::ProbeRequest(proberequest) => parse_proberequest(proberequest),
                    libwifi::Frame::ProbeResponse(proberesponse) => parse_proberesponse(proberesponse),
                    libwifi::Frame::AssociationRequest(associationrequest) => parse_assosiationrequest(associationrequest),
                    libwifi::Frame::AssociationResponse(associationresposnse) => parse_assosiationresponse(associationresposnse),
                    libwifi::Frame::Rts(rts) => parse_RTS(rts),
                    libwifi::Frame::Cts(cts) => parse_CTS(cts),
                    libwifi::Frame::Ack(ack) => parse_ACK(ack),
                    libwifi::Frame::BlockAckRequest(blockackrequest) => parse_blockackrequest(blockackrequest),
                    libwifi::Frame::BlockAck(blockack) => parse_blockack(blockack),
                    libwifi::Frame::Data(data) => parse_data(data),
                    libwifi::Frame::NullData(nulldata) => parse_nulldata(nulldata),
                    libwifi::Frame::QosData(qosdata) => parse_qosdata(qosdata),
                    libwifi::Frame::QosNull(qosnull) => parse_qosnull(qosnull),
                }
            }
        }
    }
}

fn convert_mac_hex(macadd: MacAddress) -> String {
    // TODO: convet macaddress from Decimal to Hex
    // Divide the number by 16.
    // Get the integer quotient for the next iteration.
    // Get the remainder for the hex digit.
    // Repeat the steps until the quotient is equal to 0.
    return "test".to_string();
}

// TODO: add the corect output for each function. ie beacon pushes beacon...
fn parse_beacon(beacon: Beacon) {
    println!("Beacon");
    println!("{:?}", beacon.station_info.ssid);
}

fn parse_proberequest(proberequest: ProbeRequest) {
    println!("Probe Request");
}

fn parse_proberesponse(proberesponse: ProbeResponse) {
    println!("Probe Response");
}

fn parse_assosiationrequest(associationrequest: AssociationRequest) {
    println!(" Association Request");
}

fn parse_assosiationresponse(associationresponse: AssociationResponse) {
    println!("Association Response");
}

fn parse_RTS(rts: Rts) {
    println!("RTS");
}

fn parse_CTS(cts: Cts) {
    println!("CTS");
}

fn parse_ACK(ack: Ack) {
    println!("ACK");
}

fn parse_blockackrequest(blockackrequest: BlockAckRequest) {
    println!("Block ACK Request");
}

fn parse_blockack(blockack: BlockAck) {
    println!("Block ACK");
}

fn parse_data(data: Data) {
    println!("Data");
}

fn parse_nulldata(nulldata: NullData) {
    println!("Null Data");
}

fn parse_qosdata(qosdata: QosData) {
    println!("QOS Data");
}

fn parse_qosnull(qosnull: QosNull) {
    println!("QOS Null");
}
