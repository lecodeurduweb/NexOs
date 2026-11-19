//! Network Device Abstraction & Board NIC Drivers.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    NotInitialized,
    LinkDown,
    FrameTooLarge,
    TxTimeout,
    HardwareError,
}

/// Generic layer-2 Ethernet frame device trait.
pub trait NetDevice: Send {
    fn name(&self) -> &str;
    fn mac_addr(&self) -> [u8; 6];
    fn link_up(&self) -> bool;
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), NetError>;
    fn recv_frame(&mut self, out: &mut [u8]) -> Option<usize>;
}

pub mod genet;
