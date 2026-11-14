//! USB transport for the Beagle analyzers, over `nusb`.

use super::{
    opcode, unique_id_from_serial, Command, DeviceType, FirmwareVersion, COMMAND_IN_EP,
    COMMAND_LEN, COMMAND_OUT_EP, PRODUCT_IDS, STREAM_EP, UNPROGRAMMED_ID, VENDOR_ID,
};
use futures_lite::future::{block_on, or};
use nusb::transfer::{Completion, ControlIn, ControlType, Recipient, RequestBuffer};
use std::fmt;
use std::time::Duration;

/// The library waits 50 ms for each half of a command round trip.
const COMMAND_TIMEOUT: Duration = Duration::from_millis(50);
/// Vendor request the library sends to firmware 2.x devices on open (bmRequestType 0xc0).
const INFO_REQUEST: u8 = 0xb8;
const INFO_LEN: u16 = 14;

#[derive(Debug)]
pub enum BeagleError {
    Usb(nusb::Error),
    Transfer(nusb::transfer::TransferError),
    Timeout,
    ShortReply(usize),
}

impl fmt::Display for BeagleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BeagleError::Usb(err) => write!(f, "USB error: {err}"),
            BeagleError::Transfer(err) => write!(f, "transfer failed: {err}"),
            BeagleError::Timeout => write!(f, "the analyzer did not answer in time"),
            BeagleError::ShortReply(len) => write!(f, "reply of {len} bytes, expected {COMMAND_LEN}"),
        }
    }
}

impl std::error::Error for BeagleError {}

impl From<nusb::Error> for BeagleError {
    fn from(err: nusb::Error) -> Self {
        BeagleError::Usb(err)
    }
}

impl From<nusb::transfer::TransferError> for BeagleError {
    fn from(err: nusb::transfer::TransferError) -> Self {
        BeagleError::Transfer(err)
    }
}

/// An attached analyzer, found by [`find_devices`].
#[derive(Debug, Clone)]
pub struct BeagleInfo {
    pub device: nusb::DeviceInfo,
    pub firmware: FirmwareVersion,
    pub unique_id: Option<u32>,
    /// True for a bare Cypress FX2 that has no Total Phase firmware yet.
    pub unprogrammed: bool,
}

impl BeagleInfo {
    pub fn device_type(&self) -> Option<DeviceType> {
        self.unique_id.map(DeviceType::from_unique_id)
    }
}

/// Lists Total Phase analyzers, plus unprogrammed FX2 chips (`04b4:00f3`) as the library does.
pub fn find_devices() -> Result<Vec<BeagleInfo>, BeagleError> {
    Ok(nusb::list_devices()?
        .filter_map(|device| {
            let ids = (device.vendor_id(), device.product_id());
            let unprogrammed = ids == UNPROGRAMMED_ID;
            if !unprogrammed && !(ids.0 == VENDOR_ID && PRODUCT_IDS.contains(&ids.1)) {
                return None;
            }
            Some(BeagleInfo {
                firmware: FirmwareVersion::from_bcd(device.device_version()),
                unique_id: device.serial_number().map(unique_id_from_serial),
                unprogrammed,
                device,
            })
        })
        .collect())
}

/// An open analyzer with interface 0 claimed.
pub struct Beagle {
    pub info: BeagleInfo,
    device: nusb::Device,
    interface: nusb::Interface,
}

impl Beagle {
    pub fn open(info: BeagleInfo) -> Result<Beagle, BeagleError> {
        let device = info.device.open()?;
        let interface = device.claim_interface(0)?;
        Ok(Beagle { info, device, interface })
    }

    /// The 14-byte block that firmware 2.x returns to vendor request 0xb8. Its layout is not known.
    pub fn info_block(&self) -> Result<Vec<u8>, BeagleError> {
        let request = ControlIn {
            control_type: ControlType::Vendor,
            recipient: Recipient::Device,
            request: INFO_REQUEST,
            value: 0,
            index: 0,
            length: INFO_LEN,
        };
        let completion = with_timeout(self.interface.control_in(request), Duration::from_millis(500))?;
        Ok(completion.into_result()?)
    }

    /// Sends one command packet and returns the analyzer's 64-byte reply (`bg_cmd_roundtrip`,
    /// 0xfd1c).
    pub fn command(&self, command: &Command) -> Result<Command, BeagleError> {
        with_timeout(self.interface.bulk_out(COMMAND_OUT_EP, command.0.to_vec()), COMMAND_TIMEOUT)?
            .into_result()?;
        let reply = with_timeout(self.interface.bulk_in(COMMAND_IN_EP, RequestBuffer::new(1024)), COMMAND_TIMEOUT)?
            .into_result()?;
        if reply.len() < COMMAND_LEN {
            return Err(BeagleError::ShortReply(reply.len()));
        }
        let mut bytes = [0u8; COMMAND_LEN];
        bytes.copy_from_slice(&reply[..COMMAND_LEN]);
        Ok(Command(bytes))
    }

    /// A command whose answer is the byte after the opcode, such as [`opcode::QUERY_0E`].
    pub fn query(&self, op: u16) -> Result<u8, BeagleError> {
        Ok(self.command(&Command::new(op, &[]))?.result_byte())
    }

    pub fn write_register(&self, register: u8, data: &[u8]) -> Result<(), BeagleError> {
        for packet in Command::register_write(register, data, self.info.firmware) {
            self.command(&packet)?;
        }
        Ok(())
    }

    /// Reads up to `max` bytes of capture stream from EP 0x82. Feed them to
    /// [`super::stream::Parser`].
    pub fn read_stream(&self, max: usize, timeout: Duration) -> Result<Vec<u8>, BeagleError> {
        match with_timeout(self.interface.bulk_in(STREAM_EP, RequestBuffer::new(max)), timeout) {
            Err(BeagleError::Timeout) => Ok(Vec::new()),
            other => Ok(other?.into_result()?),
        }
    }

    pub fn device(&self) -> &nusb::Device {
        &self.device
    }
}

/// Waits for a transfer, cancelling it (by dropping the future) after `timeout`.
fn with_timeout<T>(
    transfer: impl std::future::Future<Output = Completion<T>>,
    timeout: Duration,
) -> Result<Completion<T>, BeagleError> {
    block_on(or(async { Ok(transfer.await) }, async {
        async_io::Timer::after(timeout).await;
        Err(BeagleError::Timeout)
    }))
}

/// Re-exported so callers do not need the opcode module path for the common queries.
pub use opcode::{QUERY_0E, QUERY_15};
