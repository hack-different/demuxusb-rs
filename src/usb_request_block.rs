
pub enum USBDirection {
    DirectionNone,
    DirectionIn,
    DirectionOut,
}

pub enum USBSpeed {
    SpeedUnknown,
    SpeedLow,
    SpeedFull,
    SpeedHigh,
    SpeedSuper,
}

const USB_ENDPOINT_IN_MASK: u8 = 0x80;
const USB_ENDPOINT_OUT_MASK: u8 = 0x80;
const USB_ENDPOINT_ID: u8 = 0x7F;

const APPLE_VID: u16 = 0x05ac;
const USB_CLASS_APPLICATION_SPECIFIC: u8 = 0xFF;
const USB_SUBCLASS_DFU: u8 = 0x01;
const APPLE_SUBCLASS_USBMUX: u8 = 0xFE;
const APPLE_PROTOCOL_USBMUX2: u8 = 0x02;

enum URBRecordType {
    OutTransaction,
    OutPacket,
    Data0Packet,
    Data1Packet,
    AckPacket,
    NyetPacket,
    PingPacket,
    PingAck,
}

#[repr(u16)]
enum AppleUSBDeviceID {
    IRecvRecoveryMode1 = 0x1280,
    IRecvRecoveryMode2 = 0x1281,
    IRecvRecoveryMode3 = 0x1282,
    IRecvRecoveryMode4 = 0x1283,
    IRecvWtfMode = 0x1222,
    IRecvDfuMode = 0x1227,
    DebugUsb = 0x1881
}


pub struct USBRequestBlock {
    pub direction: USBDirection,
    pub speed: USBSpeed,
    pub device_number: u8,
    pub endpoint_number: u8,
    pub index: u32,
    pub index_ns: u64,
    pub duration_ns: u64,
    pub data: Vec<u8>,
}

impl USBRequestBlock {
    pub fn is_unconfigured(&self) -> bool {
        return self.device_number == 0;
    }

    pub fn is_control(&self) -> bool {
        return self.endpoint_number == 0;
    }
}

pub struct USBDevice {

}