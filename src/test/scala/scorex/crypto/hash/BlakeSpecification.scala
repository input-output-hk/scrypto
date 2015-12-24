package scorex.crypto.hash

class BlakeSpecification extends HashTest {

  hashCheckString(Blake256,
    Map(
      "" -> "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a",
      "The quick brown fox jumps over the lazy dog" -> "7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7"
    )
  )

  hashCheckString(Blake512,
    Map(
      "" -> "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8",
      "The quick brown fox jumps over the lazy dog" -> "1f7e26f63b6ad25a0896fd978fd050a1766391d2fd0471a77afb975e5034b7ad2d9ccf8dfb47abbbe656e1b82fbc634ba42ce186e8dc5e1ce09a885d41f43451"
    )
  )

}
