package scorex.crypto.hash

class StribogSpecification extends HashTest {

  hashCheckString(Stribog256,
    Map(
      "" -> "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
      "The quick brown fox jumps over the lazy dog" -> "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4",
      "The quick brown fox jumps over the lazy dog." -> "36816a824dcbe7d6171aa58500741f2ea2757ae2e1784ab72c5c3c6c198d71da"
    )
  )

  hashCheckString(Stribog512,
    Map(
      "" -> "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a")
  )

}