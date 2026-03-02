#![allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]
pub type uint8_t = u8;
pub type uint16_t = u16;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct libusb_control_setup {
    pub bmRequestType: uint8_t,
    pub bRequest: uint8_t,
    pub wValue: uint16_t,
    pub wIndex: uint16_t,
    pub wLength: uint16_t,
}
#[no_mangle]
pub static mut LIBUSB_PACKED: libusb_control_setup = libusb_control_setup {
    bmRequestType: 0,
    bRequest: 0,
    wValue: 0,
    wIndex: 0,
    wLength: 0,
};
