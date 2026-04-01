use std::iter::Map;
use uuid::Uuid;
use bitflags::bitflags;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum USBDirection {
    DirectionNone,
    DirectionIn,
    DirectionOut,
}

pub enum USBClassCode {
    PerInterface = 0x00,
    Audio = 0x01,
    Communications = 0x02,
    HumanInterfaceDevice = 0x03,
    Physical = 0x05,
    Image = 0x06,
    Printer = 0x07,
    MassStorage = 0x08,
    Hub = 0x09,
    Data = 0x0a,
    SmartCard = 0x0b,
    ContentSecurity = 0x0d,
    Video = 0x0e,
    PersonalHealthcare = 0x0f,
    DiagnosticDevice = 0xdc,
    Wireless = 0xe0,
    Miscellaneous = 0xef,
    Application = 0xfe,
    VendorSpecific = 0xff
}

pub enum USBDescriptorType {
    Device = 0x01,
    Configuration = 0x02,
    String = 0x03,
    Interface = 0x04,
    Endpoint = 0x05,
    InterfaceAssociation = 0x0b,
    BOS = 0x0f,
    DeviceCapability = 0x10,
    HID = 0x21,
    Report = 0x22,
    Physical = 0x23,
    Hub = 0x29,
    SuperspeedHub = 0x2a,
    SuperSpeedEndpointCompanion = 0x30
}

pub enum USBDescriptor {
    Device(USBDeviceDescriptor),
    Configuration(USBConfigDescriptor),
    String(String),
    Interface(InterfaceDescriptor),
    Endpoint(EndpointDescriptor),
    InterfaceAssociation(InterfaceAssociationDescriptor),
    BOS(BinaryObjectStoreDescriptor),
    DeviceCapability(BosDevCapabilityDescriptor),
    HID(u8),
    Report(u8),
}

enum USBBinaryObjectStoreType {
    LibusbBtWirelessUsbDeviceCapability = 1,
    LibusbBtUsb20Extension = 2,
    LibusbBtSsUsbDeviceCapability = 3,
    LibusbBtContainerId = 4,
}

const DEVICE_SIZE: u8   =        18;
const CONFIG_SIZE  : u8    =     9;
const INTERFACE_SIZE : u8   =    9;
const ENDPOINT_SIZE  : u8  =     7;
const ENDPOINT_AUDIO_SIZE : u8   =   9;
const HUB_NONVAR_SIZE : u8 =     7;
const SS_ENDPOINT_COMPANION_SIZE: u8 =   6;
const BOS_SIZE: u8    =      5;
const DEVICE_CAPABILITY_SIZE : u8 =  3;
const INTERFACE_ASSOCIATION_SIZE : u8 =  8;

/* BOS descriptor sizes */
const BT_USB_2_0_EXTENSION_SIZE: u8 =   7;
const BT_SS_USB_DEVICE_CAPABILITY_SIZE : u8 =10;
const BT_SSPLUS_USB_DEVICE_CAPABILITY_SIZE: u8 =12;
const BT_CONTAINER_ID_SIZE : u8   = 20;
const BT_PLATFORM_DESCRIPTOR_MIN_SIZE : u8  =   20;

const ENDPOINT_ADDRESS_MASK: u8 =        0x0f ;
const ENDPOINT_DIR_MASK : u8 =       0x80;

#[derive(Debug, PartialEq, Eq)]
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

const TRANSFER_TYPE_MASK :u8 =      0x03;

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
    RecoveryMode1 = 0x1280,
    RecoveryMode2 = 0x1281,
    RecoveryMode3 = 0x1282,
    RecoveryMode4 = 0x1283,
    WheresTheFirmwareMode = 0x1222,
    DeviceFirmwareUpdateMode = 0x1227,
    DebugUsb = 0x1881
}

bitflags! {
    /// A set of permissions for a user.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct USBAttributes: u8 {
        const Control  = 0x00;
        const Isochronous = 0x01;
        const Bulk  = 0x02;
        const Interrupt = 0x03;
        const NoSynchonisation = 0x00;
        const Asynchronous = 0x04;
        const Adaptive = 0x05;
        const Synchronous = 0x06;
        const DataEndpoint = 0x00;
        const FeedbackEndpoint = 0x07;
        const ExplicitFeedbackDataEndpoint = 0x08;
    }
}

pub struct USBSetAddress {
    device_id: u8
}

pub struct USBGetDeviceDescriptor {
    device_id: u8,
    index: u8
}

#[derive(Debug)]
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
        self.device_number == 0
    }

    pub fn is_control(&self) -> bool {
        self.endpoint_number == 0
    }
}


pub struct USBDevice {
    global_id: Uuid,
    local_device_id: u8,
    configurations: Map<u8, USBConfiguration>,
    endpoints: Map<u8, USBEndpoint>,
}

pub struct USBConfiguration {
    interfaces: Map<u8, USBInterface>
}

pub struct USBInterface {
    configuration_id: u8,
    input_id: u8,
    output_id: u8,
}

pub struct USBEndpoint {
    endpoint_id: u8,
    direction: USBDirection,
    urbs: Vec<USBRequestBlock>
}

struct USBDeviceDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    bcd_usb: u16,
    device_class: USBClassCode,
    device_sub_class: u8,
    device_protocol: u8,
    max_packet_size: u8,
    vendor_id: u16,
    product_id: u16,
    bcd_device: u16,
    index_manufacturer: u8,
    index_product: u8,
    index_serial_number: u8,
    configuration_count: u8,
}

struct EndpointDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    endpoint_address: u8,
    attributes: USBAttributes,
    max_packet_size: u16,
    polling_interval: u8,
    refresh: u8,
    synch_address: u8,
    extra: *const u8,
    extra_length: u32,
}

struct InterfaceAssociationDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    first_interface: u8,
    interface_count: u8,
    function_class: u8,
    function_sub_class: u8,
    function_protocol: u8,
    function_index: u8,
}

struct InterfaceAssociationDescriptorArray {
    iad: InterfaceAssociationDescriptor,
    length: u32,
}

struct InterfaceDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    interface_id: u8,
    interface_alternative: u8,
    endpoint_count: u8,
    interface_class: USBClassCode,
    interface_sub_class: u8,
    interface_protocol: u8,
    interface_index: u8,
    endpoint: EndpointDescriptor,
    extra: *const u8,
    extra_length: u32,
}

struct USBInterfaceDescriptor {
    altsetting: InterfaceDescriptor,
    alternate_setting_count: u32,
}

struct USBConfigDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    total_length: u16,
    interface_count: u8,
    configuration_id: u8,
    configuration_index: u8,
    attributes: USBAttributes,
    max_power: u8,
     interface: USBInterfaceDescriptor,
    extra: *const u8,
    extra_length: u32,
}

struct SsEndpointCompanionDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    max_burst: u8,
    attributes: USBAttributes,
    bytes_per_interval: u16,
}

struct BosDevCapabilityDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    compatability_type: USBBinaryObjectStoreType,
    dev_capability_data: *const u8,
}

struct BinaryObjectStoreDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    total_length: u16,
    device_capability_count: u8,
    dev_capability: Vec<BosDevCapabilityDescriptor>,
}

struct LibusbUsb20ExtensionDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    compatability_type: USBBinaryObjectStoreType,
    attributes: USBAttributes,
}

struct SsUsbDeviceCapabilityDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    compatability_type: USBBinaryObjectStoreType,
    attributes: USBAttributes,
    speed_supported: u16,
    functionality_support: u8,
    u1dev_exit_lat: u8,
    u2dev_exit_lat: u16,
}

enum SuperSpeedPlusSublinkAttributeSublinkType {
    AttrTypeSym = 0,
    AttrTypeAsym = 1,
}

enum SuperspeedplusSublinkAttributeSublinkDirection {
    LibusbSsplusAttrDirRx = 0,
    LibusbSsplusAttrDirTx = 1,
}

enum SuperspeedplusSublinkAttributeExponent {
    LibusbSsplusAttrExpBps = 0,
    LibusbSsplusAttrExpKbs = 1,
    LibusbSsplusAttrExpMbs = 2,
    LibusbSsplusAttrExpGbs = 3,
}

enum SuperspeedplusSublinkAttributeLinkProtocol {
    SsplusAttrProtSs = 0,
    LibusbSsplusAttrProtSsplus = 1,
}

enum LibusbSuperspeedplusSublinkAttributeExponent { LibusbSsplusAttrExpBps = 0 , LibusbSsplusAttrExpKbs = 1 , LibusbSsplusAttrExpMbs = 2 , LibusbSsplusAttrExpGbs = 3 }

enum LibusbSuperspeedplusSublinkAttributeSublinkType {
    LibusbSsplusAttrTypeSym = 0,
    LibusbSsplusAttrTypeAsym = 1,
}
struct LibusbSsplusSublinkAttribute {
    super_speed_id: u8,
    exponent: LibusbSuperspeedplusSublinkAttributeExponent,
    sublink_type: LibusbSuperspeedplusSublinkAttributeSublinkType,
    direction: SuperspeedplusSublinkAttributeSublinkDirection,
    protocol: SuperspeedplusSublinkAttributeLinkProtocol,
    mantissa: u16,
}

struct SsplusUsbDeviceCapabilityDescriptor {
    num_sublink_speed_attributes: u8,
    num_sublink_speed_ids: u8,
    ssid: u8,
    min_rx_lane_count: u8,
    min_tx_lane_count: u8,
    sublink_speed_attributes:  [LibusbSsplusSublinkAttribute],
}

struct ContainerIdDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    compatability_type: USBBinaryObjectStoreType,
    reserved: u8,
    container_id : [u8; 16],
}

struct USBPlatformDescriptor {
    length: u8,
    descriptor_type: USBDescriptorType,
    compatability_type: USBBinaryObjectStoreType,
    reserved: u8,
    platform_capability_uuid: [u8; 16],
    capability_type: [u8],
}