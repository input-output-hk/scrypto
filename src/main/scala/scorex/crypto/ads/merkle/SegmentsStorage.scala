package scorex.crypto.ads.merkle

import scorex.crypto.ads.MapDBStorage

class SegmentsStorage(fileName: String) extends MapDBStorage[Long, Array[Byte]](fileName: String)