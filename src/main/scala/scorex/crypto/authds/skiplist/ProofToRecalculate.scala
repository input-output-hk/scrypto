package scorex.crypto.authds.skiplist

/**
 *
 * @param newEl - element to put to that position
 * @param proof - old proof of newEl and element left to it
 */
case class ProofToRecalculate(newEl: SLElement, proof: ExtendedSLProof)