package scorex.utils

object Bytes {

  /**
    * Returns the values from each provided array combined into a single array. For example,
    * {@code concat(new byte[] {a, b}, new byte[] {}, new byte[] {c}} returns the array {@code {a, b,
   * c}}.
    *
    * @param arrays zero or more {@code byte} arrays
    * @return a single array containing all the values from the source arrays, in order
    */
  def concat(arrays: Array[Byte]*): Array[Byte] = {
    var length = 0
    val nArrays = arrays.length
    var i = 0
    while (i < nArrays) {
      length += arrays(i).length
      i += 1
    }
    val result = new Array[Byte](length)
    var pos = 0
    i = 0
    while (i < nArrays) {
      val array = arrays(i)
      System.arraycopy(array, 0, result, pos, array.length)
      pos += array.length
      i += 1
    }
    result
  }
  
}
