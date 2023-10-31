import mug
import gleam/io
import gleam/result
import rtmp/protocol/handshake

pub fn main() {
  let assert Ok(socket) =
    mug.new("ingest.aircast.app", port: 1935)
    |> mug.timeout(milliseconds: 2000)
    |> mug.connect()

  let handshake = handshake.new(handshake.Client)

  let assert Ok(_) = do_handshake(socket, handshake)
  io.println("handshake complete")
}

fn do_handshake(
  socket: mug.Socket,
  handshake: handshake.Handshake,
) -> Result(BitArray, handshake.Error) {
  case handshake.take_action(handshake) {
    #(handshake, handshake.Read) -> {
      // TODO: propgate error
      let assert Ok(packet) = mug.receive(socket, timeout_milliseconds: 10_000)
      use handshake <- result.try(handshake.process_bytes(handshake, packet))
      do_handshake(socket, handshake)
    }
    #(handshake, handshake.Write(bytes)) -> {
      // TODO: propgate error
      let assert Ok(Nil) = mug.send(socket, bytes)
      do_handshake(socket, handshake)
    }
    #(_, handshake.Finish(remaining_bytes)) -> Ok(remaining_bytes)
  }
}
