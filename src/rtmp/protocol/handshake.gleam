import gleam/crypto
import gleam/result.{try}
import gleam/bit_string

pub type Error {
  NeedMoreBytes
  BadVersionID
  UnknownPacket1Format
}

pub type PeerType {
  Server
  Client
}

pub opaque type Handshake {
  Handshake(
    stage: HandshakeStage,
    peer_type: PeerType,
    buffered: BitArray,
    to_send: BitArray,
  )
}

pub opaque type HandshakeStage {
  WaitingForPacket0
  WaitingForPacket1
  WaitingForPacket2
  Complete
}

pub fn new(peer_type: PeerType) -> Handshake {
  let to_send = case peer_type {
    Server -> <<>>
    Client -> {
      let random_bits = crypto.strong_random_bytes(1532 - 8)
      <<3, 0:8-unit(4), adobe_version:bits, random_bits:bits>>
    }
  }
  Handshake(
    stage: WaitingForPacket0,
    peer_type: peer_type,
    buffered: <<>>,
    to_send: to_send,
  )
}

const rtmp_packet_size = 1536

const adobe_version = <<128, 0, 7, 2>>

const fms_name = <<"Genuine Adobe Flash Media Server 001":utf8>>

const fp_name = <<"Genuine Adobe Flash Player 001":utf8>>

const random_crud = <<
  0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8, 0x2e, 0x00, 0xd0, 0xd1, 0x02,
  0x9e, 0x7e, 0x57, 0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab, 0x93, 0xb8,
  0xe6, 0x36, 0xcf, 0xeb, 0x31, 0xae,
>>

const sha256_digest_length = 32

pub type HandshakeAction {
  Read
  Write(BitArray)
  Finish(BitArray)
}

pub fn take_action(handshake: Handshake) -> #(Handshake, HandshakeAction) {
  case bit_string.byte_size(handshake.to_send), handshake.stage {
    0, Complete -> #(handshake, Finish(handshake.buffered))
    0, _ -> #(handshake, Read)
    _, _ -> #(Handshake(..handshake, to_send: <<>>), Write(handshake.to_send))
  }
}

pub fn process_bytes(
  handshake: Handshake,
  bytes: BitArray,
) -> Result(Handshake, Error) {
  case handshake, bytes {
    _, <<>> -> Ok(handshake)
    Handshake(stage: WaitingForPacket0, ..), _ ->
      parse_0(handshake, bytes)
      |> try(fn(res) {
        let #(handshake, bytes) = res
        process_bytes(handshake, bytes)
      })
    Handshake(stage: WaitingForPacket1, ..), _ ->
      parse_1(handshake, bytes)
      |> try(fn(res) {
        let #(handshake, bytes) = res
        process_bytes(handshake, bytes)
      })
    Handshake(stage: WaitingForPacket2, ..), _ -> parse_2(handshake, bytes)
    Handshake(stage: Complete, ..), _ -> Ok(handshake)
  }
}

fn parse_0(handshake: Handshake, bytes: BitArray) {
  case bytes {
    <<>> -> Ok(#(handshake, <<>>))
    <<3, rest:bits>> ->
      Ok(#(Handshake(..handshake, stage: WaitingForPacket1), rest))
    _ -> Error(BadVersionID)
  }
}

fn parse_1(handshake: Handshake, bytes: BitArray) {
  case <<handshake.buffered:bits, bytes:bits>> {
    <<handshake_bytes:bytes-size(rtmp_packet_size), rest:bits>> -> {
      // TODO: if this errors, handle original style RTMP handshake
      // https://docs.rs/rml_rtmp/0.8.0/src/rml_rtmp/handshake/mod.rs.html#319-334
      use digest <- try(digest_for_received_packet(
        handshake_bytes,
        case handshake {
          Handshake(peer_type: Server, ..) -> fp_name
          Handshake(peer_type: Client, ..) -> fms_name
        },
      ))

      let output_data =
        crypto.strong_random_bytes(rtmp_packet_size - sha256_digest_length)
      let key_prefix = case handshake {
        Handshake(peer_type: Server, ..) -> fms_name
        Handshake(peer_type: Client, ..) -> fp_name
      }
      let key = <<key_prefix:bits, random_crud:bits>>
      let hmac1 = calc_hmac(digest, key)
      let hmac2 = calc_hmac(output_data, hmac1)
      let output_packet = <<output_data:bits, hmac2:bits>>

      Ok(#(
        Handshake(
          ..handshake,
          stage: WaitingForPacket2,
          buffered: <<>>,
          to_send: <<handshake.to_send:bits, output_packet:bits>>,
        ),
        rest,
      ))
    }
    bytes -> Ok(#(Handshake(..handshake, buffered: bytes), <<>>))
  }
}

fn parse_2(handshake: Handshake, bytes: BitArray) {
  case <<handshake.buffered:bits, bytes:bits>> {
    <<_:bytes-size(rtmp_packet_size), rest:bits>> -> {
      // TODO: handle original style RTMP handshake
      // https://docs.rs/rml_rtmp/0.8.0/src/rml_rtmp/handshake/mod.rs.html#379-388

      // TODO: p2 verification
      // https://docs.rs/rml_rtmp/0.8.0/src/rml_rtmp/handshake/mod.rs.html#398-410

      Ok(Handshake(..handshake, stage: Complete, buffered: rest, to_send: <<>>))
    }
    bytes -> Ok(Handshake(..handshake, buffered: bytes))
  }
}

fn digest_for_received_packet(bytes: BitArray, key: BitArray) {
  let v1_offset = client_digest_offset(bytes)
  let v1_parts = message_parts(bytes, v1_offset)
  let v1_hmac = calc_hmac(<<v1_parts.before:bits, v1_parts.after:bits>>, key)

  let v2_offset = server_digest_offset(bytes)
  let v2_parts = message_parts(bytes, v2_offset)
  let v2_hmac = calc_hmac(<<v2_parts.before:bits, v2_parts.after:bits>>, key)

  case True {
    _ if v1_hmac == v1_parts.digest -> Ok(v1_parts.digest)
    _ if v2_hmac == v2_parts.digest -> Ok(v2_parts.digest)
    _ -> Error(UnknownPacket1Format)
  }
}

fn client_digest_offset(bytes: BitArray) {
  let assert <<_:bytes-size(8), b1, b2, b3, b4, _:bits>> = bytes
  { { b1 + b2 + b3 + b4 } % 728 } + 12
}

fn server_digest_offset(bytes: BitArray) {
  let assert <<_:bytes-size(772), b1, b2, b3, b4, _:bits>> = bytes
  { { b1 + b2 + b3 + b4 } % 728 } + 776
}

type MessageParts {
  MessageParts(before: BitArray, after: BitArray, digest: BitArray)
}

fn message_parts(bytes: BitArray, digest_offset: Int) -> MessageParts {
  let assert <<
    part1:bytes-size(digest_offset),
    digest:bytes-size(sha256_digest_length),
    part2:bits,
  >> = bytes
  MessageParts(part1, part2, digest)
}

fn calc_hmac(bytes: BitArray, key: BitArray) -> BitArray {
  crypto.hmac(bytes, crypto.Sha256, key)
}
