package scorex.crypto.storage.auth

import scorex.crypto.storage.MapDBStorage

class SegmentsStorage(fileName: String) extends MapDBStorage[Long, Array[Byte]](fileName: String)