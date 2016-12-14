package scorex.crypto.hash

class SkeinSpecification extends HashTest {

  hashCheckString(Skein256,
    Map(
      "" -> "39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621",
      "The quick brown fox jumps over the lazy dog" -> "b3250457e05d3060b1a4bbc1428bc75a3f525ca389aeab96cfa34638d96e492a",
      "The quick brown fox jumps over the lazy dog." -> "41e829d7fca71c7d7154ed8fc8a069f274dd664ae0ed29d365d919f4e575eebb"
    )
  )

  hashCheckString(Skein512,
    Map(
      "" -> "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
    //TODO
    )
  )

}
