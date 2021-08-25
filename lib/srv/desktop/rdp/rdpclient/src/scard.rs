use crate::errors::{invalid_data_error, NTSTATUS_OK};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_traits::{FromPrimitive, ToPrimitive};
use rdp::model::data::Message;
use rdp::model::error::*;
use std::io::{Cursor, Read};

type Payload = Cursor<Vec<u8>>;

pub struct Client {}

impl Client {
    pub fn new() -> Self {
        Self {}
    }

    pub fn ioctl(&self, code: u32, input: Payload) -> RdpResult<(u32, Vec<u8>)> {
        let mut input = input;
        let code = IoctlCode::from_u32(code).ok_or(invalid_data_error(&format!(
            "invalid I/O control code value {:#010x}",
            code
        )))?;

        match code {
            IoctlCode::SCARD_IOCTL_ACCESSSTARTEDEVENT => {
                let req = ScardAccessStartedEvent_Call::decode(&mut input)?;
                info!("got {:?}", req);
                let resp = Long_Return::new(ReturnCode::SCARD_S_SUCCESS).encode()?;
                info!("sending SCARD_S_SUCCESS");
                Ok((NTSTATUS_OK, resp))
            }
            IoctlCode::SCARD_IOCTL_ESTABLISHCONTEXT => {
                let req = EstablishContext_Call::decode(&mut input)?;
                info!("got {:?}", req);
                let resp =
                    EstablishContext_Return::new(ReturnCode::SCARD_S_SUCCESS, Context::new(1))
                        .encode()?;
                info!("sending SCARD_S_SUCCESS");
                Ok((NTSTATUS_OK, resp))
            }
            _ => Err(invalid_data_error(&format!(
                "unimplemented I/O control code: {:?}",
                code
            ))),
        }
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[allow(non_camel_case_types)]
enum IoctlCode {
    SCARD_IOCTL_ESTABLISHCONTEXT = 0x00090014,
    SCARD_IOCTL_RELEASECONTEXT = 0x00090018,
    SCARD_IOCTL_ISVALIDCONTEXT = 0x0009001C,
    SCARD_IOCTL_LISTREADERGROUPSA = 0x00090020,
    SCARD_IOCTL_LISTREADERGROUPSW = 0x00090024,
    SCARD_IOCTL_LISTREADERSA = 0x00090028,
    SCARD_IOCTL_LISTREADERSW = 0x0009002C,
    SCARD_IOCTL_INTRODUCEREADERGROUPA = 0x00090050,
    SCARD_IOCTL_INTRODUCEREADERGROUPW = 0x00090054,
    SCARD_IOCTL_FORGETREADERGROUPA = 0x00090058,
    SCARD_IOCTL_FORGETREADERGROUPW = 0x0009005C,
    SCARD_IOCTL_INTRODUCEREADERA = 0x00090060,
    SCARD_IOCTL_INTRODUCEREADERW = 0x00090064,
    SCARD_IOCTL_FORGETREADERA = 0x00090068,
    SCARD_IOCTL_FORGETREADERW = 0x0009006C,
    SCARD_IOCTL_ADDREADERTOGROUPA = 0x00090070,
    SCARD_IOCTL_ADDREADERTOGROUPW = 0x00090074,
    SCARD_IOCTL_REMOVEREADERFROMGROUPA = 0x00090078,
    SCARD_IOCTL_REMOVEREADERFROMGROUPW = 0x0009007C,
    SCARD_IOCTL_LOCATECARDSA = 0x00090098,
    SCARD_IOCTL_LOCATECARDSW = 0x0009009C,
    SCARD_IOCTL_GETSTATUSCHANGEA = 0x000900A0,
    SCARD_IOCTL_GETSTATUSCHANGEW = 0x000900A4,
    SCARD_IOCTL_CANCEL = 0x000900A8,
    SCARD_IOCTL_CONNECTA = 0x000900AC,
    SCARD_IOCTL_CONNECTW = 0x000900B0,
    SCARD_IOCTL_RECONNECT = 0x000900B4,
    SCARD_IOCTL_DISCONNECT = 0x000900B8,
    SCARD_IOCTL_BEGINTRANSACTION = 0x000900BC,
    SCARD_IOCTL_ENDTRANSACTION = 0x000900C0,
    SCARD_IOCTL_STATE = 0x000900C4,
    SCARD_IOCTL_STATUSA = 0x000900C8,
    SCARD_IOCTL_STATUSW = 0x000900CC,
    SCARD_IOCTL_TRANSMIT = 0x000900D0,
    SCARD_IOCTL_CONTROL = 0x000900D4,
    SCARD_IOCTL_GETATTRIB = 0x000900D8,
    SCARD_IOCTL_SETATTRIB = 0x000900DC,
    SCARD_IOCTL_ACCESSSTARTEDEVENT = 0x000900E0,
    SCARD_IOCTL_RELEASETARTEDEVENT = 0x000900E4,
    SCARD_IOCTL_LOCATECARDSBYATRA = 0x000900E8,
    SCARD_IOCTL_LOCATECARDSBYATRW = 0x000900EC,
    SCARD_IOCTL_READCACHEA = 0x000900F0,
    SCARD_IOCTL_READCACHEW = 0x000900F4,
    SCARD_IOCTL_WRITECACHEA = 0x000900F8,
    SCARD_IOCTL_WRITECACHEW = 0x000900FC,
    SCARD_IOCTL_GETTRANSMITCOUNT = 0x00090100,
    SCARD_IOCTL_GETREADERICON = 0x00090104,
    SCARD_IOCTL_GETDEVICETYPEID = 0x00090108,
}

#[derive(Debug)]
struct RPCEStreamHeader {
    version: u8,
    endianness: RPCEEndianness,
    common_header_length: u16,
    filler: u32,
}

impl RPCEStreamHeader {
    fn new() -> Self {
        Self {
            version: 1,
            endianness: RPCEEndianness::LittleEndian,
            common_header_length: 8,
            filler: 0xcccccccc,
        }
    }
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u8(self.version)?;
        w.write_u8(self.endianness.to_u8().unwrap())?;
        w.write_u16::<LittleEndian>(self.common_header_length)?;
        w.write_u32::<LittleEndian>(self.filler)?;
        Ok(w)
    }
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        let header = Self {
            version: payload.read_u8()?,
            endianness: RPCEEndianness::from_u8(payload.read_u8()?).ok_or(invalid_data_error(
                "invalid endianness in RPCE stream header",
            ))?,
            common_header_length: payload.read_u16::<LittleEndian>()?,
            filler: payload.read_u32::<LittleEndian>()?,
        };
        // TODO(awly): implement big endian parsing support
        if let RPCEEndianness::LittleEndian = header.endianness {
            Ok(header)
        } else {
            Err(invalid_data_error(
                "server returned big-endian data, parsing not implemented",
            ))
        }
    }
}

fn encode_response(resp: Vec<u8>) -> RdpResult<Vec<u8>> {
    let mut resp = resp;
    let mut buf = RPCEStreamHeader::new().encode()?;
    buf.append(&mut resp);
    Ok(buf)
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[allow(non_camel_case_types)]
enum RPCEEndianness {
    BigEndian = 0x00,
    LittleEndian = 0x10,
}

#[derive(Debug)]
struct RPCETypeHeader {
    object_buffer_length: u32,
    filler: u32,
}

impl RPCETypeHeader {
    fn new(len: u32) -> Self {
        Self {
            object_buffer_length: len,
            filler: 0,
        }
    }
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u32::<LittleEndian>(self.object_buffer_length)?;
        w.write_u32::<LittleEndian>(self.filler)?;
        Ok(w)
    }
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        Ok(Self {
            object_buffer_length: payload.read_u32::<LittleEndian>()?,
            filler: payload.read_u32::<LittleEndian>()?,
        })
    }
}

fn encode_struct(resp: Vec<u8>) -> RdpResult<Vec<u8>> {
    let mut resp = resp;
    let mut buf = RPCETypeHeader::new(resp.length() as u32).encode()?;
    buf.append(&mut resp);
    Ok(buf)
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct ScardAccessStartedEvent_Call {
    unused: u32,
}

impl ScardAccessStartedEvent_Call {
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        Ok(Self {
            unused: payload.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct Long_Return {
    return_code: ReturnCode,
}

impl Long_Return {
    fn new(return_code: ReturnCode) -> Self {
        Self { return_code }
    }
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_i64::<LittleEndian>(self.return_code.to_i64().unwrap())?;
        Ok(encode_response(encode_struct(w)?)?)
    }
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct EstablishContext_Call {
    scope: Scope,
}

impl EstablishContext_Call {
    fn decode(payload: &mut Payload) -> RdpResult<Self> {
        let header = RPCEStreamHeader::decode(payload)?;
        let header = RPCETypeHeader::decode(payload)?;
        let scope = payload.read_u64::<LittleEndian>()?;
        Ok(Self {
            scope: Scope::from_u64(scope).ok_or(invalid_data_error(&format!(
                "invalid smart card scope {:?}",
                scope
            )))?,
        })
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[allow(non_camel_case_types)]
enum Scope {
    SCARD_SCOPE_USER = 0x00000000,
    SCARD_SCOPE_TERMINAL = 0x00000001,
    SCARD_SCOPE_SYSTEM = 0x00000002,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
struct EstablishContext_Return {
    return_code: ReturnCode,
    context: Context,
}

impl EstablishContext_Return {
    fn new(return_code: ReturnCode, context: Context) -> Self {
        Self {
            return_code,
            context,
        }
    }
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_i64::<LittleEndian>(self.return_code.to_i64().unwrap())?;
        w.append(&mut self.context.encode()?);
        Ok(encode_response(encode_struct(w)?)?)
    }
}

#[derive(Debug)]
struct Context {
    length: u64,
    value: u64,
}

impl Context {
    fn new(val: u64) -> Self {
        Self {
            length: 8,
            value: val,
        }
    }
    fn encode(&self) -> RdpResult<Vec<u8>> {
        let mut w = vec![];
        w.write_u64::<LittleEndian>(self.length)?;
        w.write_u64::<LittleEndian>(self.value)?;
        Ok(encode_struct(w)?)
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive)]
#[allow(non_camel_case_types)]
enum ReturnCode {
    SCARD_S_SUCCESS = 0x00000000,
    SCARD_F_INTERNAL_ERROR = 0x80100001,
    SCARD_E_CANCELLED = 0x80100002,
    SCARD_E_INVALID_HANDLE = 0x80100003,
    SCARD_E_INVALID_PARAMETER = 0x80100004,
    SCARD_E_INVALID_TARGET = 0x80100005,
    SCARD_E_NO_MEMORY = 0x80100006,
    SCARD_F_WAITED_TOO_LONG = 0x80100007,
    SCARD_E_INSUFFICIENT_BUFFER = 0x80100008,
    SCARD_E_UNKNOWN_READER = 0x80100009,
    SCARD_E_TIMEOUT = 0x8010000A,
    SCARD_E_SHARING_VIOLATION = 0x8010000B,
    SCARD_E_NO_SMARTCARD = 0x8010000C,
    SCARD_E_UNKNOWN_CARD = 0x8010000D,
    SCARD_E_CANT_DISPOSE = 0x8010000E,
    SCARD_E_PROTO_MISMATCH = 0x8010000F,
    SCARD_E_NOT_READY = 0x80100010,
    SCARD_E_INVALID_VALUE = 0x80100011,
    SCARD_E_SYSTEM_CANCELLED = 0x80100012,
    SCARD_F_COMM_ERROR = 0x80100013,
    SCARD_F_UNKNOWN_ERROR = 0x80100014,
    SCARD_E_INVALID_ATR = 0x80100015,
    SCARD_E_NOT_TRANSACTED = 0x80100016,
    SCARD_E_READER_UNAVAILABLE = 0x80100017,
    SCARD_P_SHUTDOWN = 0x80100018,
    SCARD_E_PCI_TOO_SMALL = 0x80100019,
    SCARD_E_ICC_INSTALLATION = 0x80100020,
    SCARD_E_ICC_CREATEORDER = 0x80100021,
    SCARD_E_UNSUPPORTED_FEATURE = 0x80100022,
    SCARD_E_DIR_NOT_FOUND = 0x80100023,
    SCARD_E_FILE_NOT_FOUND = 0x80100024,
    SCARD_E_NO_DIR = 0x80100025,
    SCARD_E_READER_UNSUPPORTED = 0x8010001A,
    SCARD_E_DUPLICATE_READER = 0x8010001B,
    SCARD_E_CARD_UNSUPPORTED = 0x8010001C,
    SCARD_E_NO_SERVICE = 0x8010001D,
    SCARD_E_SERVICE_STOPPED = 0x8010001E,
    SCARD_E_UNEXPECTED = 0x8010001F,
    SCARD_E_NO_FILE = 0x80100026,
    SCARD_E_NO_ACCESS = 0x80100027,
    SCARD_E_WRITE_TOO_MANY = 0x80100028,
    SCARD_E_BAD_SEEK = 0x80100029,
    SCARD_E_INVALID_CHV = 0x8010002A,
    SCARD_E_UNKNOWN_RES_MSG = 0x8010002B,
    SCARD_E_NO_SUCH_CERTIFICATE = 0x8010002C,
    SCARD_E_CERTIFICATE_UNAVAILABLE = 0x8010002D,
    SCARD_E_NO_READERS_AVAILABLE = 0x8010002E,
    SCARD_E_COMM_DATA_LOST = 0x8010002F,
    SCARD_E_NO_KEY_CONTAINER = 0x80100030,
    SCARD_E_SERVER_TOO_BUSY = 0x80100031,
    SCARD_E_PIN_CACHE_EXPIRED = 0x80100032,
    SCARD_E_NO_PIN_CACHE = 0x80100033,
    SCARD_E_READ_ONLY_CARD = 0x80100034,
    SCARD_W_UNSUPPORTED_CARD = 0x80100065,
    SCARD_W_UNRESPONSIVE_CARD = 0x80100066,
    SCARD_W_UNPOWERED_CARD = 0x80100067,
    SCARD_W_RESET_CARD = 0x80100068,
    SCARD_W_REMOVED_CARD = 0x80100069,
    SCARD_W_SECURITY_VIOLATION = 0x8010006A,
    SCARD_W_WRONG_CHV = 0x8010006B,
    SCARD_W_CHV_BLOCKED = 0x8010006C,
    SCARD_W_EOF = 0x8010006D,
    SCARD_W_CANCELLED_BY_USER = 0x8010006E,
    SCARD_W_CARD_NOT_AUTHENTICATED = 0x8010006F,
    SCARD_W_CACHE_ITEM_NOT_FOUND = 0x80100070,
    SCARD_W_CACHE_ITEM_STALE = 0x80100071,
    SCARD_W_CACHE_ITEM_TOO_BIG = 0x80100072,
}
