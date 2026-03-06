use minicbor::decode::Decoder;
use minicbor::decode::Error;

pub trait SubCbor<'a> {
    fn sub_cbor(&mut self) -> Result<&'a [u8], Error>;
}

impl<'b> SubCbor<'b> for Decoder<'b> {
    fn sub_cbor(&mut self) -> Result<&'b [u8], Error> {
        let start = self.position();
        self.skip()?; // Skip over the full component section
        let end = self.position();
        self.input().get(start..end).ok_or(Error::end_of_input())
    }
}
