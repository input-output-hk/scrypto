package scorex.crypto.authds.skiplist

case class SkipListUpdate(toDelete: Seq[SLElement] = Seq(), toInsert: Seq[SLElement] = Seq(),
                          toUpdate: Seq[SLElement] = Seq())
