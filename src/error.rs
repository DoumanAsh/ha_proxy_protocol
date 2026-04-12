use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
///Possible parsing errors
pub enum ParseError {
    ///Proxy protocol version 1 is not valid utf-8 string
    InvalidProxy1Str,
    ///Proxy protocol version 1 has more components that allowed
    InvalidProxy1Overflow,

    ///Proxy protocol version 2 with invalid LOCAL command
    InvalidProxy2WrongLocalCmd,

    ///Incomplete input
    MissingSrcPort,
    ///Incomplete input
    MissingSrcAddr,
    ///Source addr has invalid port
    InvalidSrcPort,
    ///Source addr is not valid IPv4
    InvalidSrcIpv4,
    ///Source addr is not valid IPv6
    InvalidSrcIpv6,

    ///Incomplete input
    MissingDstPort,
    ///Incomplete input
    MissingDstAddr,
    ///Destination addr has invalid port
    InvalidDstPort,
    ///Destination addr is not valid IPv4
    InvalidDstIpv4,
    ///Destination addr is not valid IPv6
    InvalidDstIpv6,

    ///Indicates corrupted TLV payload.
    MalformedTlv,

    ///Unrecognized transport type
    InvalidTransport,
    ///Valid transport type but payload has insufficient data to extract data
    InvalidTransportSize,
    ///Proxy protocol has invalid signature
    InvalidProxySig,
    ///Incomplete input
    Incomplete,
}

impl fmt::Display for ParseError {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProxy1Str => fmt.write_str("Not a valid protocol version 1. Non-utf8 string"),
            Self::InvalidProxy1Overflow => fmt.write_str("Not a valid protocol version 1. Too many parts"),

            Self::InvalidProxy2WrongLocalCmd => fmt.write_str("Not a valid protocol version 2. LOCAL command with invalid transport"),

            Self::MissingSrcPort => fmt.write_str("Not enough bytes to read proxy protocol message. Missing src port"),
            Self::MissingSrcAddr => fmt.write_str("Not enough bytes to read proxy protocol message. Missing src addr"),
            Self::InvalidSrcPort => fmt.write_str("Source addr has invalid port"),
            Self::InvalidSrcIpv4 => fmt.write_str("Source addr is not valid IPv4"),
            Self::InvalidSrcIpv6 => fmt.write_str("Source addr is not valid IPv6"),

            Self::MissingDstPort => fmt.write_str("Not enough bytes to read proxy protocol message. Missing dst port"),
            Self::MissingDstAddr => fmt.write_str("Not enough bytes to read proxy protocol message. Missing dst addr"),
            Self::InvalidDstPort => fmt.write_str("Destination addr has invalid port"),
            Self::InvalidDstIpv4 => fmt.write_str("Destination addr is not valid IPv4"),
            Self::InvalidDstIpv6 => fmt.write_str("Destination addr is not valid IPv6"),

            Self::MalformedTlv => fmt.write_str("Valid proxy version contains malformed TLV payload"),

            Self::InvalidTransport => fmt.write_str("Invalid protocol version. Not a valid transport type"),
            Self::InvalidTransportSize => fmt.write_str("Found valid transport type, but cannot extract proxy info due to insufficient payload size"),
            Self::InvalidProxySig => fmt.write_str("Not a valid protocol version. Missing header"),
            Self::Incomplete => fmt.write_str("Not enough bytes to read proxy protocol message. Need more bytes"),
        }
    }
}
