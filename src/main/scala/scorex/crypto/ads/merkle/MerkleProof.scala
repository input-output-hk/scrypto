package scorex.crypto.ads.merkle

import scorex.crypto.hash.CryptographicHash._

case class MerkleProof(index: Position, merklePath: Seq[Digest])