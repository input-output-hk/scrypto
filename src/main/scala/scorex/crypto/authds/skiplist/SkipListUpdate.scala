package scorex.crypto.authds.skiplist

case class SkipListUpdate(toDelete: Seq[SLElement], toInsert: Seq[SLElement])
