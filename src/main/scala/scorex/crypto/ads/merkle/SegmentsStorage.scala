package scorex.crypto.ads.merkle

import scorex.crypto.ads.{MapDBStorage, LazyIndexedBlobStorage}

class SegmentsStorage(override val fileName: String) extends LazyIndexedBlobStorage with MapDBStorage[Long, Array[Byte]]