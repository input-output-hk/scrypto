package scorex.crypto.storage.auth

import scorex.crypto.hash.CryptographicHash._

case class DataBlockSignature(index: Position, merklePath: Seq[Digest])